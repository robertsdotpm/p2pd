import asyncio
import json
import re
import random
from .test_init import *
from .daemon import Daemon
from .http_server_lib import RESTD

class ToxicBase():
    def __init__(self, name=None, direction=None, toxicity=None):
        self.name = name
        self.direction = direction
        self.toxicity = toxicity

    def setup(self, base):
        self.name = base.name
        self.direction = base.direction
        self.toxicity = base.toxicity
        return self
    
    def should_run(self):
        p = min(int(self.toxicity * 100), 100)
        r = random.randrange(1, 101)
        if r <= p:
            return True
        else:
            return False
        
    async def placeholder(self, msg, dest_pipe):
        return msg, dest_pipe
        
async def toxic_router(msg, src_pipe, dest_pipe, toxics):
    for toxic in toxics:
        if toxic.should_run():
            ret = await async_wrap_errors(
                toxic.run(msg, dest_pipe)
            )

            if ret is None:
                continue
            else:
                msg, dest_pipe = ret

            # Dest pipe has been closed.
            if dest_pipe is None:
                return
            
            # Message filtered.
            if msg is None:
                return

    await async_wrap_errors(
        dest_pipe.send(msg)
    )

class ToxicLatency(ToxicBase):
    def __init__(self):
        super().__init__(self)

    def set_params(self, latency, jitter):
        self.latency = latency
        self.jitter = jitter
        return self
    
    async def run(self, msg, dest_pipe):
        # Simulate different message arrival times.
        jitter = 0
        if self.jitter:
            jitter = random.randrange(0, self.jitter)
            if random.choice([0, 1]):
                jitter = -jitter

        # Return control to other coroutines.
        ms = self.latency + jitter
        if ms > 0:
            await asyncio.sleep(ms / 1000)

        return msg, dest_pipe
    
class ToxicBandwidthLimit(ToxicBase):
    def set_params(self, rate):
        self.rate = rate # KB/s

        # Track amount of bw used across coroutines.
        # This prevents exceeding the bw allocation.
        self.used = 0

        # Convert rate to bytes per 100 ms.
        # If rate is 0 then there's no limit.
        self.rate_ms = int((self.rate * 1024) / 10)
        return self
    
    async def get_bandwidth(self, n):
        # Wait for some positive amount of bw to become available.
        # Other coroutines may be using all the bw.
        bw = 0
        while bw <= 0 and self.rate_ms:
            bw = self.rate_ms - self.used

            """
            Allocations are recorded before doing a sleep since this
            allows other coroutines to run which may then get their
            own allocations and end up going over the limit. Doing
            the change immediately after ensures the bandwidth limit
            is respected between coroutines.
            """
            if bw > 0:
                # Use only as much as needed.
                bw = min(n, bw)
                self.used += bw

            """
            Give other coroutines a chance to use their bw.
            Sleeping is always done to start with even if
            there was initial bw available because otherwise
            multiple coroutines could accidentally exceed the limit.
            """
            await asyncio.sleep(0.1)

        # Return the allocated amount.
        return bw

    # Could be improved with memoryview.
    async def run(self, msg, dest_pipe):
        unsent = len(msg)
        while unsent > 0:
            # Block for an allocation of bandwidth.
            # Checks every 100 ms.
            bw = await self.get_bandwidth(unsent)

            # Once an allocation is given use that amount.
            await dest_pipe.send(msg[:bw])
            msg = msg[bw:]

            # Adjust counters after await operations.
            # This is for safety to maintain integrity of self.used.
            unsent -= bw
            self.used -= bw

        # Message sent so return.
        return None, dest_pipe

class ToxicSlowClose(ToxicBase):
    def set_params(self, ms):
        self.ms = ms
        return self

    async def run(self, msg, dest_pipe):
        # Close is already patched so undo.
        # Allows for later slow closes to replace this.
        if hasattr(dest_pipe, "regular_close"):
            dest_pipe.close = dest_pipe.regular_close

        # Save old close function.
        dest_pipe.regular_close = dest_pipe.close

        # New function to add slow close.
        async def slow_close():
            await asyncio.sleep(self.ms / 1000)
            await dest_pipe.regular_close()

        # Replace old close with slow close.
        dest_pipe.close = slow_close

        # Replace this class function instance
        # so it only runs once.
        self.run = self.placeholder

class ToxicTimeout(ToxicBase):
    def set_params(self, ms):
        self.start_time = time.time()
        self.ms = ms
        if self.ms:
            self.ms = ms / 1000.0

        return self

    async def run(self, msg, dest_pipe):
        # Calculate duration of active toxic.
        cur_time = time.time()
        duration = cur_time - self.start_time

        # Close if timeout reached.
        if self.ms:
            remaining = self.ms - min(self.ms, duration)
            if remaining:
                await asyncio.sleep(remaining)

            await dest_pipe.close()
            return None, None

        # Block data transmission.
        return None, dest_pipe
    
class ToxicResetPeer(ToxicBase):
    def set_params(self, ms):
        self.start_time = time.time()
        self.ms = ms
        if self.ms:
            self.ms = ms / 1000.0
            
        return self

    async def run(self, msg, dest_pipe):
        # Discard unacked data on close.
        if not hasattr(dest_pipe, "reset_peer_hook"):
            dest_pipe.reset_peer_hook = 1
            linger = struct.pack('ii', 1, 0)
            dest_pipe.sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_LINGER,
                linger
            )

        # Calculate duration of active toxic.
        cur_time = time.time()
        duration = cur_time - self.start_time

        # Close if timeout reached.
        if self.ms:
            if duration >= self.ms:
                await dest_pipe.close()
            else:
                return msg, dest_pipe
        else:
            await dest_pipe.close()

        # Block data transmission.
        return None, None

class ToxicLimitData(ToxicBase):
    def set_params(self, n):
        self.n = n
        self.total = 0
        return self

    async def run(self, msg, dest_pipe):
        self.total += len(msg)
        if self.total >= self.n:
            await dest_pipe.close()
            return None, None
        else:
            return msg, dest_pipe
        
class ToxicSlicer(ToxicBase):
    def set_params(self, avg_size, size_var, delay):
        self.avg_size = avg_size
        self.size_var = size_var
        self.delay = delay
        return self
    
    def chunk(self, start, end):
        """
        Base case:
        If the size is within the random variation,
        or already less than the average size, just
        return it. Otherwise split the message into
        chunks of average size +/- size variation.
        """
        offsets = []
        seg_len = end - start
        if seg_len - self.avg_size <= self.size_var:
            return [start, end]
        
        # Build chunk offset list.
        # End offset overlaps with start offset.
        # This is not a mistake.
        p_start = start
        while 1:
            # Calculate a random variation.
            # May be positive or negative.
            rand_len = rand_rang(0, (self.size_var * 2) + 1)
            change = rand_len - self.size_var

            # Increase start pointer by random variation.
            # Avoid underflows with max.
            p_end = p_start + max((self.avg_size + change), 1)

            # Record the chunk offsets.
            # Avoid overflows with min.
            offsets += [p_start, min(p_end, end)]

            # Increase pointer for next segment.
            p_start = offsets[-1]

            # Should never be greater than end
            # but this will be used as the cutoff.
            if offsets[-1] >= end:
                break

        return offsets

    async def run(self, msg, dest_pipe):
        offsets = self.chunk(0, len(msg))
        if self.delay:
            await asyncio.sleep(self.delay / 1000)

        for i in range(1, len(offsets), 2):
            chunk = msg[offsets[i - 1]:offsets[i]]
            if self.delay:
                await asyncio.sleep(self.delay / 1000)

            await dest_pipe.send(chunk)

        # Messages are processed so return None.
        return None, dest_pipe

# You need a way to force new messages to wait for past.
class ToxiTunnelServer(Daemon):
    def __init__(self, name):
        super().__init__()
        self.name = name
        self.upstream_pipe = None
        self.upstream_toxics = {}
        self.downstream_toxics = {}
        self.clients = []

    def get_toxic(self, name):
        if name in self.upstream_toxics:
            return self.upstream_toxics
        
        if name in self.downstream_toxics:
            return self.downstream_toxics
        
        return None

    async def close(self):
        # Ensure all clients are closed.
        for client in self.clients:
            await client.close()

        # Close connection to upstream if it's set.
        if self.upstream_pipe is not None:
            await self.upstream_pipe.close()

        # Close the listen server itself.
        await super().close()

    # Record a list of tunnel clients to relay messages from upstream to.
    async def up_cb(self, msg, client_tup, con_pipe):
        # Make sure they are removed when the connection closes.
        async def end_cb(msg, client_tup, end_pipe):
            if con_pipe in self.clients:
                self.clients.remove(con_pipe)

        con_pipe.add_end_cb(end_cb)
        self.clients.append(con_pipe)

    # Redirect msgs from upstream to clients with toxics.
    def set_upstream(self, pipe):
        async def msg_cb(msg, client_tup, upstream_pipe):
            pipe.transport.pause_reading()
            tasks = []
            for client in self.clients:
                tasks.append(
                    toxic_router(
                        msg,
                        pipe,
                        client,
                        d_vals(self.downstream_toxics)
                    )
                )

            if len(tasks):
                await asyncio.gather(
                    *tasks,
                    return_exceptions=True
                )

            pipe.transport.resume_reading()

        pipe.add_msg_cb(msg_cb)
        self.upstream_pipe = pipe

    # Redirect msg from clients to upstream with toxics.
    async def msg_cb(self, msg, client_tup, down_pipe):
        down_pipe.transport.pause_reading()
        await toxic_router(
            msg,
            down_pipe,
            self.upstream_pipe,
            d_vals(self.upstream_toxics)
        )
        down_pipe.transport.resume_reading()

class ToxiMainServer(RESTD):
    def __init__(self, interfaces):
        self.__name__ = "ToxiMainServer"
        super().__init__()
        self.interfaces = interfaces
        self.tunnel_servs = {}

    @RESTD.GET(["version"])
    async def show_version(self, v, pipe):
        return {
            "title": "Toxid",
            "author": "Matthew@Roberts.PM", 
            "version": "1.0.0",
            "error": 0
        }

    @RESTD.POST(["proxies"])
    async def create_tunnel_server(self, v, pipe):
        j = v["body"]

        # This is a request to close a tunnel.
        if j["enabled"] == False:
            # Check tunnel exists.
            tunnel_name = v["name"]["proxies"]
            if tunnel_name not in self.tunnel_servs:
                return {
                    "error": "tunnel name not found."
                }

            # Close server and delete record of tunnel.
            tunnel_serv = self.tunnel_servs[tunnel_name]
            await tunnel_serv.close()
            del self.tunnel_servs[tunnel_name]

            # Indicate tunnel is closed.
            return {
                "name": tunnel_name,
                "enabled": False,
                "toxics": []
            }
        
        # Otherwise it's a new create call.
        try:
            tup_pattern = "([\s\S]+):([0-9]+)$"
            bind_ip, bind_port = re.findall(
                tup_pattern,
                j["listen"]
            )[0]

            # Disable bind port.
            bind_port = int(bind_port)
            if not bind_port:
                bind_port = None
        except:
            log_exception()
            return {
                "error": "did not find listen details for create tunnel."
            }

        # Return more descriptive errors for debugging.
        try:
            # Build listen route.
            route = await pipe.route.interface.route().bind(
                ips=bind_ip,
                port=bind_port
            )

            # Start the tunnel server.
            tunnel_serv = ToxiTunnelServer(name=j["name"])
            bind_port, pipe = await tunnel_serv.add_listener(
                pipe.sock.type,
                route
            )
        except:
            log_exception()
            return {
                "error": f"cant bind to {bind_ip}:{bind_port}"
            }

        # Extract destination IP.
        try:
            dest_ip, dest_port = re.findall(
                tup_pattern,
                j["upstream"]
            )[0]
        except IndexError:
            return {
                "error": "upstream create tunnel field malformed."
            }

        # rewrite this to use an interface that supports
        # dest AF
        use_if = None
        dest_ipr = IPRange(dest_ip)
        for interface in self.interfaces:
            if dest_ipr.af in interface.supported():
                use_if = interface

        # Could not find suitable interface.
        if use_if is None:
            return {
                "error": "no interfaces for that address family."
            }

        # Try connect to upstream.
        proto = j.get("proto", TCP)
        try:
            # Resolve upstream address.
            up_route = await use_if.route().bind()
            dest = (dest_ip, dest_port)

            # Connect to upstream.
            upstream = await pipe_open(
                proto,
                dest,
                up_route,
            )
        except:
            return {
                "error": f"upstream res failure {dest_ip}:{dest_port}"
            }

        # Did the endpoint succeed.
        if upstream is None:
            return {
                "error": f"upstream failure {dest_ip}:{dest_port}"
            }

        # Add upstream to tunnel server.
        tunnel_serv.set_upstream(upstream)

        # If zero was passed convert to port no.
        self.tunnel_servs[j["name"]] = tunnel_serv

        # Return response
        return {
            "name": j["name"],
            "listen": f"{bind_ip}:{bind_port}",
            "upstream": j["upstream"],
            "proto": int(proto),
            "enabled": True,
            "toxics": []
        }

    @RESTD.POST(["proxies"], ["toxics"])
    async def add_new_toxic(self, v, pipe):
        j = v["body"]
        attrs = j["attributes"]
        proxy_name = v["name"]["proxies"]
        if proxy_name not in self.tunnel_servs:
            return {
                "error": "tunnel name not found"
            }
        
        # Make sure name doesn't exist.
        serv = self.tunnel_servs[proxy_name]
        if serv.get_toxic(j["name"]) is not None:
            return {
                "error": "toxic name already exists."
            }

        # Create toxic.
        toxic = base = ToxicBase(j["name"], j["stream"], j["toxicity"])

        # Clauses for all the toxics.
        if j["type"] == "slow_close":
            toxic = ToxicSlowClose().set_params(
                ms=attrs["delay"]
            ).setup(base)

        if j["type"] == "bandwidth":
            toxic = ToxicBandwidthLimit().set_params(
                rate=attrs["rate"]
            ).setup(base)

        if j["type"] == "timeout":
            toxic = ToxicTimeout().set_params(
                ms=attrs["timeout"]
            ).setup(base)

        if j["type"] == "slicer":
            toxic = ToxicSlicer().set_params(
                avg_size=attrs["average_size"],
                size_var=attrs["size_variation"],
                delay=attrs["delay"]
            ).setup(base)
    
        if j["type"] == "latency":
            toxic = ToxicLatency().set_params(
                latency=attrs["latency"],
                jitter=attrs["jitter"]
            ).setup(base)

        if j["type"] == "reset":
            toxic = ToxicResetPeer().set_params(
                ms=attrs["timeout"]
            ).setup(base)

        if j["type"] == "limit_data":
            toxic = ToxicLimitData().set_params(
                n=attrs["bytes"]
            ).setup(base)

        # Add toxic to tunnel server.
        if j["stream"] == "upstream":
            toxics = serv.upstream_toxics
        else:
            toxics = serv.downstream_toxics
        toxics[j["name"]] = toxic

        # Response.
        return j

    @RESTD.DELETE(["proxies"], ["toxics"])
    async def del_new_toxic(self, v, pipe):
        proxy_name = v["name"]["proxies"]
        toxic_name = v["name"]["toxics"]
        if proxy_name in self.tunnel_servs:
            tunnel = self.tunnel_servs[proxy_name]
            toxics = tunnel.get_toxic(toxic_name)
            if toxics is not None:
                del toxics[toxic_name]

        return b""


    # Ensure all tunnel servers are also closed.
    async def close(self):
        for tunnel_serv in d_vals(self.tunnel_servs):
            await tunnel_serv.close()

        await super().close()

asyncio.set_event_loop_policy(SelectorEventPolicy())

"""
class TestToxiServer(unittest.IsolatedAsyncioTestCase):

    async def test_toxi_server(self):
        #ret = api_route_closure("/proxies/test") ([["proxies"], ["toxics"]])
        #print(ret)
        #return


        got_n, got_p = api_route_closure("/test")([])
        want_n = {}
        want_p = {0: "test"}
        assert(got_n == want_n and got_p == want_p)

        got_n, got_p = api_route_closure("/test")([["test"]])
        want_p = {}
        want_n = {"test": "test"}
        assert(got_n == want_n and got_p == want_p)

        got_n, got_p = api_route_closure("/test/val")([["test"]])
        want_p = {}
        want_n = {"test": "val"}
        assert(got_n == want_n and got_p == want_p)

        got_n, got_p = api_route_closure("/test/val/xx/yy/aa")([["test"], ["yy", "bb"]])
        want_p = {0: 'xx'}
        want_n = {'test': 'val', 'yy': 'aa'}
        assert(got_n == want_n and got_p == want_p)

        got_n, got_p = api_route_closure("/test/val")([["test"]])
        want_n = {"test": "val"}
        want_p = {}
        assert(got_n == want_n and got_p == want_p)

        got_n, got_p = api_route_closure("/a/b")([["a", 0], ["b", 1]])
        want_n = {"a": 0, "b": 1}
        want_p = {}
        assert(got_n == want_n and got_p == want_p)
        #print(got_n, got_p)
        #assert(got == want)

        i = await Interface().start_local(skip_resolve=True)
        route = await i.route().bind(ips="127.0.0.1", port=8475)
        server = ToxiMainServer([i])
        await server.listen_specific(
            [[route, TCP]]
        )

        addr = await Address("localhost", 8475, route)
        client = ToxiClient(addr)
        await client.start()

        # Create a new tunnel from toxiproxi to google.
        dest = await Address("www.google.com", 80, client.addr.route)
        tunnel = await client.new_tunnel(dest)
        assert(isinstance(tunnel, ToxiTunnel))

        downstream = ToxiToxic().downstream()
        toxic = downstream.add_latency(100)
        await tunnel.new_toxic(toxic)

        print(f"Tunnel serv port = {tunnel.port}")
        print(d_vals(server.tunnel_servs)[0].servers)
        s = d_vals(server.tunnel_servs)[0].servers[0]
        print(s)
        print(s[2].sock.getsockname())
        tun_pipe, tun_tup = await tunnel.get_pipe()
        print(tun_tup)
        await tun_pipe.send(b"test", tun_pipe)

        tunnel_serv = d_vals(server.tunnel_servs)[0]
        print(tunnel_serv.clients)
        # assert(len(tunnel_serv.clients) == 0)
        print("close tun pipe")
        await tun_pipe.close()
        await asyncio.sleep(3)
        #await server.close()
        print(tunnel_serv.clients)
        await asyncio.sleep(1)
        #print(s[2].tcp_server_task)

        
        #print(s)

        #
        #ask_exit()
"""

if __name__ == '__main__':
    pass
