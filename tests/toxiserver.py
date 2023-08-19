import asyncio
import json
import re
import random
from p2pd.test_init import *
from p2pd import *
from toxiclient import ToxiClient, ToxiTunnel, ToxiToxic

"""
new tunnel response:

b'{"name":"gxU1jLqsno","listen":"127.0.0.1:54916","upstream":"142.250.70.196:80","enabled":true,"toxics":[]}'


@GET("/base", {'required': 'default'}, optional={})
async def base(self, vars, client_tup, pipe):
    pass
    
/base/...
0    1

[["name", default, r"regex"]]

toxic:
    ...

    return data if it hasnt modified it, pipe

toxic_router(msg, src_pipe, dest_pipe, toxics):
    for toxic in toxics:
        msg, dest_pipe = await toxic(msg, dest_pipe)
        if dest_pipe is None:
            break
    
    await dest_pipe.send(msg)
            
whats the difference between slow_close, add_timeout, and reset_peer? they all seem to be the same?

    prob shutdown but look it up

todo:
    list of toxic implementations and their socket behaviors
//          optional optional
"""

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
        
async def toxic_router(msg, src_pipe, dest_pipe, toxics):
    for toxic in toxics:
        if toxic.should_run():
            msg, dest_pipe = await toxic(msg, dest_pipe)
            if dest_pipe is None:
                break
    
    await dest_pipe.send(msg)

class ToxicLatency(ToxicBase):
    def set_params(self, latency, jitter):
        self.latency = latency
        self.jitter = jitter
        return self

    async def toxic(self, msg, dest_pipe):
        # Simulate different message arrival times.
        jitter = random.randrange(0, self.jitter)
        if random.choice([0, 1]):
            jitter = -jitter

        # Return control to other coroutines.
        ms = self.latency + jitter
        if ms > 0:
            await asyncio.sleep(ms)

        return msg, dest_pipe

class ToxiTunnelServer(Daemon):
    def __init__(self, name):
        super().__init__()
        self.name = name
        self.upstream_pipe = None
        self.upstream_toxics = {}
        self.downstream_toxics = {}
        self.clients = []

    # Record a list of tunnel clients to relay messages from upstream to.
    async def up_cb(self, msg, client_tup, con_pipe):
        # Make sure they are removed when the connection closes.
        async def end_cb(msg, client_tup, end_pipe):
            if end_pipe in self.clients:
                self.clients.remove(end_pipe)

        con_pipe.add_end_cb(end_cb)
        self.clients.append(con_pipe)

    # Redirect messages from upstream to clients with downstream toxics.
    def set_upstream(self, pipe):
        async def msg_cb(msg, client_tup, upstream_pipe):
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
                await asyncio.gather(*tasks)

        pipe.add_msg_cb = msg_cb
        self.upstream_pipe = pipe

    # Redirect message from clients to upstream with upstream toxics.
    async def msg_cb(self, msg, client_tup, down_pipe):
        await toxic_router(
            msg,
            down_pipe,
            self.upstream_pipe,
            d_vals(self.upstream_toxics)
        )

class ToxiMainServer(RESTD):
    def __init__(self, interfaces):
        super().__init__()
        self.interfaces = interfaces
        self.tunnel_servs = {}

    @RESTD.POST(["proxies"])
    async def create_tunnel_server(self, v, pipe):
        j = v["body"]
        tup_pattern = "([\s\S]+):([0-9]+)$"
        bind_ip, bind_port = re.findall(
            tup_pattern,
            j["listen"]
        )[0]

        # Build listen route.
        route = await pipe.route.interface.route().bind(
            ips=bind_ip,
            port=int(bind_port)
        )

        # Start the tunnel server.
        tunnel_serv = ToxiTunnelServer(name=j["name"])
        await tunnel_serv.listen_specific(
            [[route, TCP]]
        )

        # Extract destination IP.
        dest_ip, dest_port = re.findall(
            tup_pattern,
            j["upstream"]
        )[0]

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

        # Resolve upstream address.
        up_route = await use_if.route().bind()
        dest = await Address(dest_ip, dest_port, up_route)

        # Connect to upstream.
        upstream = await pipe_open(
            TCP,
            up_route,
            dest
        )

        # Add upstream to tunnel server.
        tunnel_serv.set_upstream(upstream)

        # If zero was passed convert to port no.
        bind_port = route.bind_port
        self.tunnel_servs[j["name"]] = tunnel_serv

        # Return response
        return {
            "name": j["name"],
            "listen": f"{bind_ip}:{bind_port}",
            "upstream": j["upstream"],
            "enabled": True,
            "toxics": []
        }

    @RESTD.POST(["proxies"], ["toxics"])
    async def add_new_toxic(self, v, pipe):
        j = v["body"]; attrs = j["attributes"]
        proxy_name = v["named"]["proxies"]
        if proxy_name not in self.tunnel_servs:
            return {
                "error": "tunnel name not found"
            }

        # Create toxic.
        toxic = base = ToxicBase(j["name"], j["direction"], j["toxicity"])
        if j["type"] == "latency":
            toxic = ToxicLatency().set_params(
                latency=attrs["latency"],
                jitter=attrs["jitter"]
            ).setup(base)

        # Add toxic to tunnel server.
        serv = self.tunnel_servs[proxy_name]
        if j["direction"] == "upstream":
            toxics = serv.upstream_toxics
        else:
            toxics = serv.downstream_toxics
        toxics[j["name"]] = toxic

        # Response.
        return j

    # Ensure all tunnel servers are also closed.
    async def close(self):
        for tunnel_serv in self.tunnel_servs.values():
            await tunnel_serv.close()

        await super().close()

asyncio.set_event_loop_policy(SelectorEventPolicy())

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
        client, client_tup = await tunnel.get_pipe()
        print(client_tup)
        await client.send(b"test", client_tup)
        await client.close()

        await server.close()

if __name__ == '__main__':
    main()
