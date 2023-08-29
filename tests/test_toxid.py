import platform
from p2pd.test_init import *
from p2pd.utils import *
from p2pd.net import VALID_AFS
from p2pd.win_netifaces import *

from toxiclient import *
from toxiserver import *

class TestToxid(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Create main Toxi server.
        i = await Interface().start_local(skip_resolve=True)
        route = await i.route().bind(ips="127.0.0.1", port=8475)
        self.toxid = ToxiMainServer([i])
        await self.toxid.listen_specific(
            [[route, TCP]]
        )

        # Create a Toxi client.
        toxid_addr = await Address("127.0.0.1", 8475, route)
        self.client = await ToxiClient(toxid_addr).start()

        # Setup a tunnel to a host for testing.
        # The toxi tunnels upstream is Google.
        route = i.route()
        tunnel_dest = await Address("www.google.com", 80, route)
        self.tunnel = await self.client.new_tunnel(tunnel_dest)
        assert(isinstance(self.tunnel, ToxiTunnel))

        # Use this for socket tests.
        self.net_conf = dict_child({
            "recv_timeout": 10
        }, NET_CONF)

    async def asyncTearDown(self):
        await self.toxid.close()

    async def test_add_latency(self):
        downstream = ToxiToxic().downstream()
        toxic = downstream.add_latency(2000)
        await self.tunnel.new_toxic(toxic)

        # HTTP get request to Google via a toxi tunnel.
        curl = await self.tunnel.get_curl()
        ret = await curl.vars().get("/", conf=self.net_conf)


if __name__ == '__main__':
    main()
