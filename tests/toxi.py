import asyncio
import json
import re
from p2pd.test_init import *
from p2pd import *

"""
Design doc:

Client
    - Factory that spawns Proxy objects.
    - Knowns about a single toxiproxy instance.
    - Stores a list of active proxies.

Tunnel
    - Represents a single end-point
        - returns listen port so 0 can be used.
    - Factory that handles spawning Toxics
    - Can bulk delete them, list, and add.
    - Can close itself and remove from client
    - Future: load toxics

Toxic
    - Object that stores active toxic state.
    - Can delete itself and remove from Proxy

    
it probably makes more sense to implement all the default toxics as
interfaces in toxitoxic so you dont have to manually remember what you
can do.
"""

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
    def add_latency(self, ms, jitter=0):
        self.body = self.api({
            "type": "latency",
            "attributes": {
                "latency": ms,
                "jitter": jitter
            }
        })

        return self
    
    # Limit a connection to a maximum number of kilobytes per second.
    def add_bandwidth_limit(self, KBs):
        self.body = self.api({
            "type": "rate",
            "attributes": {
                "rate": KBs,
            }
        })

        return self
    
    # Delay the TCP socket from closing until delay has elapsed.
    def add_slow_close(self, ms):
        self.body = self.api({
            "type": "slow_close",
            "attributes": {
                "delay": ms,
            }
        })

        return self
    
    """
    Stops all data from getting through, and closes the connection after timeout.
    If timeout is 0, the connection won't close, and data will be delayed
    until the toxic is removed.
    """
    def add_timeout(self, ms):
        self.body = self.api({
            "type": "timeout",
            "attributes": {
                "timeout": ms,
            }
        })

        return self
    
    """
    Simulate TCP RESET (Connection reset by peer) on the connections
    by closing the stub Input immediately or after a timeout.
    """
    def add_reset_peer(self, ms):
        self.body = self.api({
            "type": "reset_peer",
            "attributes": {
                "timeout": ms,
            }
        })

        return self
    
    # Closes connection when transmitted data exceeded limit.
    def add_limit_data(self, n):
        self.body = self.api({
            "type": "limit_data",
            "attributes": {
                "bytes": n,
            }
        })

        return self

    # Slices TCP data up into small bits, optionally
    # adding a delay between each sliced "packet".
    def add_slicer(self, n, v, ug):
        self.body = self.api({
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

        return self

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
        self.toxics.append(toxic)

    async def remove_toxic(self, toxic):
        path = f"/proxies/{self.name}/toxics/{toxic.name}"
        resp = await self.client.curl.vars().delete(path)
        print(self.client.curl.req_buf)
        print(resp.out)
        self.toxics.remove(toxic)

    async def test_list(self):
        path = f"/proxies/{self.name}"
        resp = await self.client.curl.vars().get(path)
        print(resp.out)

    async def get_pipe(self):
        # Build new route.
        route = self.client.addr.route
        route = copy.deepcopy(route)
        await route.bind()

        # Connect to the listen server for this tunnel.
        dest = await Address("localhost", self.port, route)
        pipe = await pipe_open(TCP, route, dest)
        return pipe

    # Close the tunnel on the toxiproxy instance.
    async def close(self):
        json_body = {
            "enabled": False
        }

        path = f"/proxies/{self.name}"
        resp = await self.client.curl.vars(body=json_body).post(path)
        self.client.tunnels.remove(self)

class ToxiClient():
    def __init__(self, addr):
        self.addr = addr
        self.tunnels = []

    async def start(self):
        hdrs = [[b"user-agent", b"toxiproxy-cli"]]
        self.curl = WebCurl(self.addr, hdrs=hdrs)

    async def version(self):
        resp = await self.curl.vars().get("/version")
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

        # Listen porn for the tunnel server.
        port = re.findall("127[.]0[.]0[.]1[:]([0-9]+)", to_s(resp.out))[0]
        port = to_n(port)

        # Create a new object to interact with the tunnel.
        tunnel = ToxiTunnel(name=name, port=port, client=self)
        self.tunnels.append(tunnel)

        # Return tunnel.
        return tunnel

asyncio.set_event_loop_policy(SelectorEventPolicy())
class TestToxi(unittest.IsolatedAsyncioTestCase):
    async def test_toxi(self):
        i = await Interface().start_local()
        r = i.route()

        addr = await Address("localhost", 8474, r)

        client = ToxiClient(addr)
        await client.start()

        dest = await Address("www.example.com", 80, r)
        tunnel = await client.new_tunnel(dest)

        toxic = ToxiToxic().downstream().add_latency(100)

        await tunnel.new_toxic(toxic)

        await tunnel.remove_toxic(toxic)

        print("test list")
        await tunnel.test_list()

        await tunnel.close()

        return
        hdrs = [[b"user-agent", b"toxiproxy-cli"]]
        out = await url_open(
            route=r,
            url="http://localhost:8474/version",
            headers=hdrs
        )

        print(out)

        t = """{"name": "shopify_test_redis_master",
"listen": "127.0.0.1:0",
"upstream": "www.example.com:80",
"enabled": true}"""
        r = i.route()
        d = await Address("localhost", 8474, r)
        p, resp = await http_req(
            route=r,
            dest=d,
            path=b"/proxies",
            method=b"POST",
            payload=t,
            headers=[
                [b"user-agent", b"toxiproxy-cli"],
                [b"Content-Type", b"application/json"]
            ]
        )

        print(resp.out())
            

if __name__ == '__main__':
    main()
