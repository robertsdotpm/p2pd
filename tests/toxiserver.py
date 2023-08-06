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

[["name", r"regex", default]]
//          optional optional

"""

class ToxiTunnelServer(RESTD):
    pass

class ToxiMainServer(RESTD):
    @RESTD.GET("/proxies")
    async def base(self, vars, client_tup, pipe):
        pass


asyncio.set_event_loop_policy(SelectorEventPolicy())

class TestToxiServer(unittest.IsolatedAsyncioTestCase):
    async def test_toxi_server(self):

        got = api_route_closure("/test")([])
        want = {0: "test"}
        assert(got == want)

        got = api_route_closure("/test")([["test"]])
        want = {}
        assert(got == want)

        got = api_route_closure("/test/val")([["test"]])
        want = {"test": "val"}
        assert(got == want)

        got = api_route_closure("/test/val/xx/yy/aa")([["test"], ["yy", "aa"]])
        want = {'test': 'val', 0: 'xx', 'yy': 'aa'}
        assert(got == want)

        


        print(got)

        return


        i = await Interface().start_local(skip_resolve=True)
        route = await i.route().bind(ips="127.0.0.1")
        server = ToxiMainServer([i])
        await server.listen_all(
            [route],
            [8475],
            [TCP]
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
