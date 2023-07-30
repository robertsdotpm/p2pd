import asyncio
from p2pd.test_init import *
from p2pd import *

"""
Design doc:

Client
    - Factory that spawns Proxy objects.
    - Knowns about a single toxiproxy instance.
    - Stores a list of active proxies.

Proxy
    - Represents a single end-point
        - returns listen port so 0 can be used.
    - Factory that handles spawning Toxics
    - Can bulk delete them, list, and add.
    - Can close itself and remove from client
    - Future: load toxics

Toxic
    - Object that stores active toxic state.
    - Can delete itself and remove from Proxy

"""



asyncio.set_event_loop_policy(SelectorEventPolicy())
class TestToxi(unittest.IsolatedAsyncioTestCase):
    async def test_toxi(self):
        i = await Interface().start_local()
        r = i.route()
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
