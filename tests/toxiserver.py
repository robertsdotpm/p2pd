import asyncio
import json
import re
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
//          optional optional

"""

class ToxiTunnelServer(RESTD):
    pass

class ToxiMainServer(RESTD):
    def __init__(self):
        super().__init__()
        self.tunnel_servs = []

    @RESTD.POST(["proxies"])
    async def create_tunnel_server(self, v, pipe):
        bind_pattern = "([\s\S]+):([0-9]+)$"
        bind_ip, bind_port = re.findall(
            bind_pattern,
            v["body"]["listen"]
        )[0]

        # Build listen route.
        route = await pipe.route.rebind(
            ips=bind_ip,
            port=int(bind_port)
        )

        # Start the tunnel server.
        tunnel_serv = ToxiTunnelServer()
        await tunnel_serv.listen_specific(
            [[route, TCP]]
        )


        # If zero was passed convert to port no.
        bind_port = route.bind_port
        print(bind_port)
        


asyncio.set_event_loop_policy(SelectorEventPolicy())

class TestToxiServer(unittest.IsolatedAsyncioTestCase):
    async def test_toxi_server(self):
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
        server = ToxiMainServer()
        await server.listen_specific(
            [[route, TCP]]
        )

        addr = await Address("localhost", 8475, route)
        client = ToxiClient(addr)
        await client.start()

        # Create a new tunnel from toxiproxi to google.
        dest = await Address("www.google.com", 80, client.addr.route)
        tunnel = await client.new_tunnel(dest)
        #assert(isinstance(tunnel, ToxiTunnel))

        await server.close()

if __name__ == '__main__':
    main()
