import platform
from p2pd.test_init import *
from p2pd.utils import *
from p2pd.net import VALID_AFS
from p2pd.win_netifaces import *

from toxiclient import *
from toxiserver import *

streams = lambda: [ToxiToxic().downstream(), ToxiToxic().upstream()]

class TestToxid(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Create main Toxi server.
        self.i = await Interface().start_local(skip_resolve=True)
        route = await self.i.route().bind(ips="127.0.0.1", port=8475)
        self.toxid = ToxiMainServer([self.i])
        await self.toxid.listen_specific(
            [[route, TCP]]
        )

        # Create a Toxi client.
        toxid_addr = await Address("127.0.0.1", 8475, route)
        self.client = await ToxiClient(toxid_addr).start()

        # Use this for socket tests.
        self.net_conf = dict_child({
            "recv_timeout": 10
        }, NET_CONF)

    """
    If using HTTP as the application protocol to test that
    toxics work as expected you definitely want a new tunnel each
    time since reusing the same connection for multiple requests
    makes this overly complex. At least with the code bellow
    the first toxic seems to work as expected.
    """
    async def new_tunnel(self):
        # Setup a tunnel to a host for testing.
        # The toxi tunnels upstream is Google.
        route = self.i.route()
        tunnel_dest = await Address("www.google.com", 80, route)
        tunnel = await self.client.new_tunnel(tunnel_dest)
        assert(isinstance(tunnel, ToxiTunnel))
        return tunnel

    async def asyncTearDown(self):
        await self.toxid.close()

    async def test_add_latency(self):
        # Test downstream and upstream.
        lag_amount = 2000
        for toxi_stream in streams():
            # Add the initial toxic to a new tunnel.
            tunnel = await self.new_tunnel()
            toxic = toxi_stream.add_latency(lag_amount)
            await tunnel.new_toxic(toxic)

            # HTTP get request to Google via a toxi tunnel.
            start_time = timestamp()
            curl = await tunnel.get_curl()
            ret = await curl.vars().get("/", conf=self.net_conf)
            end_time = timestamp()

            # Check data was received.
            assert(ret is not None)

            # Check lag amount.
            # It should lag.
            duration = end_time - start_time
            duration *= 1000 # Convert to ms.
            assert(duration >= (lag_amount * 0.8))

            # Check for timeout.
            timeout = (self.net_conf['recv_timeout'] * 1000) * 0.8
            assert(duration < timeout)

            # Cleanup.
            await tunnel.remove_toxic(toxic)
            await tunnel.close()

    async def test_add_timeout



if __name__ == '__main__':
    main()
