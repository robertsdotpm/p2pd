import asyncio
import json
import re
from p2pd.test_init import *
from p2pd import *

# https://github.com/Shopify/toxiproxy/tree/main#toxics
class ToxiToxic():
    def __init__(self, toxicity=1.0, name=None):
        self.toxicity = toxicity
        self.direction = None
        self.name = name or to_s(rand_plain(10))
        self.body = None

    def copy(self):
        toxic = ToxiToxic()
        toxic.direction = self.direction
        toxic.toxicity = self.toxicity
        toxic.name = self.name
        toxic.body = self.body
        return toxic

    def downstream(self):
        toxic = self.copy()
        toxic.direction = "downstream"
        return toxic
    
    def upstream(self):
        toxic = self.copy()
        toxic.direction = "upstream"
        return toxic
    
    def api(self, j):
        j["name"] = self.name
        j["stream"] = self.direction
        j["toxicity"] = self.toxicity
        return j
    
    # Add a delay to all data going through the proxy.
    # The delay is equal to latency +/- jitter.
    def add_latency(self, ms=1000, jitter=0):
        toxic = self.copy()
        toxic.body = self.api({
            "type": "latency",
            "attributes": {
                "latency": ms,
                "jitter": jitter
            }
        })

        return toxic
    
    # Limit a connection to a maximum number of kilobytes per second.
    def add_bandwidth_limit(self, KBs=100):
        toxic = self.copy()
        toxic.body = self.api({
            "type": "bandwidth",
            "attributes": {
                "rate": KBs,
            }
        })

        return toxic

    """ 
    Delay associated dest_pipe from being closed until a timeout
    eg if its downstream it will be similar to keep alive.
    If its upstream then other toxics wont be able to close it
    until that time frame.

    EOL or graceful shutdowns are ignored (I think).

    Time ------------------------------------>
    close blocked                       close
    """
    def add_slow_close(self, ms=2000):
        toxic = self.copy()
        toxic.body = self.api({
            "type": "slow_close",
            "attributes": {
                "delay": ms,
            }
        })

        return toxic
    
    """
    Doesn't forward data, and closes the connection after timeout (close())
    If timeout is 0, the connection won't close, and data will be delayed
    until the toxic is removed.

    Time ---------------------------->
    data blocked       Optional close
    """
    def add_timeout(self, ms=2000):
        toxic = self.copy()
        toxic.body = self.api({
            "type": "timeout",
            "attributes": {
                "timeout": ms,
            }
        })

        return toxic
    
    """
    Simulate TCP RESET (Connection reset by peer) on the connections
    by closing the stub Input immediately or after a timeout.

    The behavior of Close is set to discard any unsent/unacknowledged data by setting SetLinger to 0, ~= sets TCP RST flag and resets the connection.
    Drop data since it will initiate a graceful close with FIN/ACK. (io.EOF)

    Time ----------------------->
    data sent               close (DISCARD unset and unacked data!)
    """
    def add_reset_peer(self, ms=2000):
        toxic = self.copy()
        toxic.body = self.api({
            "type": "reset",
            "attributes": {
                "timeout": ms,
            }
        })

        return toxic
    
    """
    Closes connection when transmitted data exceeded limit.

    Limit counter ---------------->
    data                     close
    """
    def add_limit_data(self, n=100):
        toxic = self.copy()
        toxic.body = self.api({
            "type": "limit_data",
            "attributes": {
                "bytes": n,
            }
        })

        return toxic

    """
    Slices TCP data up into small bits, optionally
    adding a delay between each sliced "packet".

    The SlicerToxic slices data into multiple smaller packets
    to simulate real-world TCP behavior.

    Note: the docs say that this slices them into 'bits'
    but I think this is meant informally as in pieces
    rather than a unit of measurement. The pieces it means
    are really bytes (and can only mean bytes.)

    Slicer is designed so that receipt of data needs multiple
    recv calls to get the full response. E.g. it splits up
    responses into multiple packets and sends them individually.
    This is useful for testing assumptions behind protocol clients.
    """
    def add_slicer(self, n=1024, v=800, ug=20):
        toxic = self.copy()
        toxic.body = self.api({
            "type": "slicer",
            "attributes": {
                #  size in bytes of an average packet
                "average_size": n,

                # variation in bytes of an average packet < n
                "size_variation": v,

                # time in microseconds to delay each packet by
                "delay": ug
            }
        })

        return toxic

class ToxiTunnel():
    def __init__(self, name, port, client):
        self.name = name
        self.port = port
        self.client = client
        self.toxics = []

    async def new_toxic(self, toxic):
        path = f"/proxies/{self.name}/toxics"
        resp = await self.client.curl.vars(body=toxic.body).post(path)
        print(resp.out)
        assert(b"error" not in resp.out)
        self.toxics.append(toxic)

    async def remove_toxic(self, toxic):
        path = f"/proxies/{self.name}/toxics/{toxic.name}"
        resp = await self.client.curl.vars().delete(path)
        assert(resp.out == b'')
        print(resp.out)
        self.toxics.remove(toxic)

    async def test_list(self):
        path = f"/proxies/{self.name}"
        resp = await self.client.curl.vars().get(path)
        print(resp.out)
        return resp.out

    async def get_pipe(self):
        # Build new route.
        route = self.client.addr.route.interface.route()
        await route.bind()

        # Connect to the listen server for this tunnel.
        dest = await Address("localhost", self.port, route)
        pipe = await pipe_open(TCP, route, dest)
        return pipe, dest.tup
    
    async def get_curl(self):
        # Build new route.
        route = self.client.addr.route.interface.route()
        await route.bind()

        # Connect to the listen server for this tunnel.
        dest = await Address("localhost", self.port, route)
        return WebCurl(addr=dest, do_close=0)

    # Close the tunnel on the toxiproxy instance.
    async def close(self):
        json_body = {
            "enabled": False
        }

        path = f"/proxies/{self.name}"
        resp = await self.client.curl.vars(body=json_body).post(path)
        self.client.tunnels.remove(self)
        print(resp.out)
        return resp.out

class ToxiClient():
    def __init__(self, addr):
        self.addr = addr
        self.tunnels = []

    async def start(self):
        hdrs = [[b"user-agent", b"toxiproxy-cli"]]
        self.curl = WebCurl(self.addr, hdrs=hdrs)
        return self

    async def version(self):
        resp = await self.curl.vars().get("/version")
        print(resp.out)
        return resp.out

    async def new_tunnel(self, addr, name=None):
        name = name or to_s(rand_plain(10))
        json_body = {
            "name": name,
            "listen": "127.0.0.1:0",
            "upstream": f"{addr.target()}:{addr.port}",
            "enabled": True
        }

        resp = await self.curl.vars(body=json_body).post("/proxies")
        assert(b"error" not in resp.out)
        print(resp.out)

        # Listen porn for the tunnel server.
        port = re.findall("127[.]0[.]0[.]1[:]([0-9]+)", to_s(resp.out))[0]
        port = to_n(port)

        # Create a new object to interact with the tunnel.
        tunnel = ToxiTunnel(name=name, port=port, client=self)
        self.tunnels.append(tunnel)

        # Return tunnel.
        return tunnel

asyncio.set_event_loop_policy(SelectorEventPolicy())
async def test_setup(netifaces=None, client=None):
    # Suppress socket unclosed warnings.
    if not hasattr(test_setup, "netifaces"):
        if netifaces is None:
            test_setup.netifaces = await init_p2pd()
        else:
            test_setup.netifaces = netifaces
        #warnings.filterwarnings('ignore', message="unclosed", category=ResourceWarning)

    if not hasattr(test_setup, "client"):
        i = await Interface().start_local(skip_resolve=True)
        r = i.route()
        addr = await Address("localhost", 8474, r)
        client = ToxiClient(addr)
        await client.start()

    return client

"""
class TestToxi(unittest.IsolatedAsyncioTestCase):
    async def test_toxi_client_usage(self):
        client = await test_setup()

        # Create a new tunnel from toxiproxi to google.
        dest = await Address("www.google.com", 80, client.addr.route)
        tunnel = await client.new_tunnel(dest)
        assert(isinstance(tunnel, ToxiTunnel))

        # Test that adding and removing all toxics works.
        downstream = ToxiToxic().downstream()
        toxics = [
            downstream.add_latency(),
            downstream.add_bandwidth_limit(),
            downstream.add_slow_close(),
            downstream.add_timeout(),

            # Not in the windows binary -- newer toxic.
            #downstream.add_reset_peer(),
            downstream.add_limit_data(),
            downstream.add_slicer()
        ]

        # Try each toxic one by one.
        for toxic in toxics:
            print(f"adding {toxic.body['type']}")

            # Add the new toxic to the tunnel.
            await tunnel.new_toxic(toxic)
            assert(toxic in tunnel.toxics)

            # Check that there's a toxic for that tunnel.
            out = await tunnel.test_list()
            out = json.loads(to_s(out))
            assert(len(out["toxics"]))

            # Remove the toxic from the tunnel.
            await tunnel.remove_toxic(toxic)
            assert(toxic not in tunnel.toxics)

            # Check that there's no toxics for that tunnel.
            out = await tunnel.test_list()
            out = json.loads(to_s(out))
            assert(not len(out["toxics"]))

        # Will throw on error response.
        await tunnel.close()
"""

if __name__ == '__main__':
    pass
    #main()
