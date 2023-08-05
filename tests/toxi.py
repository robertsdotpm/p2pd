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
    
    def add_latency(self, ms, jitter=0):
        json_body = {
            "type": "latency",
            "attributes": {
                "latency": ms,
                "jitter": jitter
            }
        }

        self.body = self.api(json_body)
        return self

class ToxiTunnel():
    def __init__(self, name, port, client):
        self.name = name
        self.port = port
        self.client = client

    async def new_toxic(self, toxic):
        path = f"/proxies/{self.name}/toxics"
        print(toxic.body)
        resp = await self.client.curl.vars(body=toxic.body).post(path)
        print(resp.out)

    async def connect(self):
        pass

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
