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
//          optional optional

"""

class ToxiTunnelServer(RESTD):
    def __init__(self, name):
        super().__init__()
        self.name = name
        self.upstreams = []
        self.upstream_toxics = []
        self.downstream_toxics = []

    def add_upstream(self, pipe):
        self.upstreams.append(pipe)

class ToxiMainServer(RESTD):
    def __init__(self):
        super().__init__()
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

        # Resolve upstream address.
        up_route = await pipe.route.interface.route().bind()
        dest_ip, dest_port = re.findall(
            tup_pattern,
            j["upstream"]
        )[0]
        dest_port = int(dest_port)
        dest = await Address(dest_ip, dest_port, up_route)

        # Connect to upstream.
        upstream = await pipe_open(
            TCP,
            up_route,
            dest
        )

        # Add upstream to tunnel server.
        tunnel_serv.add_upstream(upstream)

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
        print(v)

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
        assert(isinstance(tunnel, ToxiTunnel))

        downstream = ToxiToxic().downstream()
        toxic = downstream.add_latency()
        await tunnel.new_toxic(toxic)

        await server.close()

if __name__ == '__main__':
    main()
