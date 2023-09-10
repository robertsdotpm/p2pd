import platform
from p2pd.test_init import *
from p2pd.utils import *
from p2pd.net import VALID_AFS
from p2pd.win_netifaces import *
from p2pd.echo_server import *

from toxiclient import *
from toxiserver import *

streams = lambda: [ToxiToxic().downstream(), ToxiToxic().upstream()]



class TestToxid(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        

        # Create main Toxi server.
        self.i = await Interface().start_local(skip_resolve=True)
        loop = asyncio.get_running_loop()
        x = loop.get_exception_handler()
        print(loop.get_debug())
        print(x)
        print(loop._exception_handler)

        route = await self.i.route().bind(ips="127.0.0.1", port=8475)
        self.toxid = ToxiMainServer([self.i])
        await self.toxid.listen_specific(
            [[route, TCP]]
        )

        # Create a Toxi client.
        toxid_addr = await Address("127.0.0.1", 8475, route)
        self.client = await ToxiClient(toxid_addr).start()

        # Create an echo server -- used for some tests.
        route = await self.i.route().bind(ips="127.0.0.1", port=7777)
        self.echod = EchoServer()
        await self.echod.listen_specific(
            [[route, TCP]]
        )

        # Address to connect to echod.
        self.echo_dest = await Address("127.0.0.1", 7777, route)

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
    async def new_tunnel(self, tunnel_dest):
        # Setup a tunnel to a host for testing.
        # The toxi tunnels upstream is Google.
        route = self.i.route()
        tunnel = await self.client.new_tunnel(tunnel_dest)
        assert(isinstance(tunnel, ToxiTunnel))
        return tunnel

    async def asyncTearDown(self):
        await self.toxid.close()
        await self.echod.close()

    async def test_add_latency(self):
        return
        # Test downstream and upstream.
        lag_amount = 2000
        tunnel_dest = await Address("www.google.com", 80, self.i.route())
        for toxi_stream in streams():
            # Add the initial toxic to a new tunnel.
            tunnel = await self.new_tunnel(tunnel_dest)
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

    async def test_limit_data(self):
        return
        send_buf = b"1" * 90
        for toxi_stream in streams():
            # Open new tunnel.
            tunnel = await self.new_tunnel(self.echo_dest)
            tunneld = d_vals(self.toxid.tunnel_servs)[0]
            up_sock = tunneld.upstream_pipe.sock

            # Add limit data toxic.
            toxic = toxi_stream.add_limit_data(100)
            await tunnel.new_toxic(toxic)
            pipe, _ = await tunnel.get_pipe()

            # We're allowed to send 90 bytes okay.
            await pipe.send(send_buf)
            recv_buf = await pipe.recv()
            assert(recv_buf == send_buf)

            # But 100 or over closes the socket.
            await pipe.send(send_buf)
            await asyncio.sleep(1)
            assert(
                # Downstream test.
                pipe.sock.fileno() == -1
                
                or

                # Upstream test.
                up_sock.fileno() == -1
            ) 

            # Cleanup.
            await pipe.close()
            await tunnel.remove_toxic(toxic)
            await tunnel.close()

    async def test_reset_peer(self):
        for toxi_stream in streams():
            # Open new tunnel.
            tunnel = await self.new_tunnel(self.echo_dest)
            tunneld = d_vals(self.toxid.tunnel_servs)[0]
            up_sock = tunneld.upstream_pipe.sock

            # Add limit data toxic.
            toxic = toxi_stream.add_reset_peer(1000)
            await tunnel.new_toxic(toxic)
            pipe, _ = await tunnel.get_pipe()

            # Should close after timeout.
            assert(up_sock.fileno() != -1)
            assert(pipe.sock.fileno() != -1)
            await asyncio.sleep(1.1)
            await pipe.send(b'test')
            await asyncio.sleep(1)
            assert(
                # Downstream test.
                pipe.sock.fileno() == -1
                
                or

                # Upstream test.
                up_sock.fileno() == -1
            ) 

            # Cleanup.
            await pipe.close()
            await tunnel.remove_toxic(toxic)
            await tunnel.close()

if __name__ == '__main__':

    main()
