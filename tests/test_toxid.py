from p2pd import *


streams = lambda: [ToxiToxic().downstream(), ToxiToxic().upstream()]

class TestToxid(unittest.IsolatedAsyncioTestCase):
    async def do_setup(self):
        # Use this for socket tests.
        net_conf = dict_child({
            "recv_timeout": 10
        }, NET_CONF)

        # Create main Toxi server.
        i = await Interface()
        toxiport = 8031
        route = await i.route().bind(ips="127.0.0.1", port=toxiport)
        toxid = ToxiMainServer([i])
        await toxid.add_listener(TCP, route)
        
        # Create a Toxi client.
        toxid_addr = ("127.0.0.1", toxiport)
        client = await ToxiClient(
            toxid_addr,
            i.route(IP4),
            net_conf
        ).start()

        # Create an echo server -- used for some tests.
        echodport = 23111
        route = await i.route().bind(ips="127.0.0.1", port=echodport)
        echod = EchoServer()
        await echod.add_listener(TCP, route)

        # Address to connect to echod.
        echo_dest = ("127.0.0.1", echodport)
        return net_conf, i, toxid, toxid_addr, client, echod, echo_dest

    """
    If using HTTP as the application protocol to test that
    toxics work as expected you definitely want a new tunnel each
    time since reusing the same connection for multiple requests
    makes this overly complex. At least with the code bellow
    the first toxic seems to work as expected.
    """
    async def new_tunnel(self, tunnel_dest, client):
        # Setup a tunnel to a host for testing.
        # The toxi tunnels upstream is Google.
        tunnel = await client.new_tunnel(tunnel_dest)
        assert(isinstance(tunnel, ToxiTunnel))
        return tunnel

    async def do_cleanup(self, toxid, echod):
        await toxid.close()
        await echod.close()

    async def test_add_latency(self):
        # Setup.
        net_conf, \
        i, \
        toxid, \
        toxid_addr, \
        client, \
        echod, \
        echo_dest = await self.do_setup()

        # Test downstream and upstream.
        lag_amount = 2000
        tunnel_dest = ("142.250.70.238", 80)
        for toxi_stream in streams():
            # Add the initial toxic to a new tunnel.
            tunnel = await self.new_tunnel(tunnel_dest, client)
            toxic = toxi_stream.add_latency(lag_amount)
            await tunnel.new_toxic(toxic)

            # HTTP get request to Google via a toxi tunnel.
            start_time = timestamp()
            curl = await tunnel.get_curl()
            ret = await curl.vars().get("/", conf=net_conf)
            end_time = timestamp()

            # Check data was received.
            assert(ret is not None)

            # Check lag amount.
            # It should lag.
            duration = end_time - start_time
            duration *= 1000 # Convert to ms.
            assert(duration >= (lag_amount * 0.8))

            # Check for timeout.
            timeout = (net_conf['recv_timeout'] * 1000) * 0.8
            assert(duration < timeout)

            # Cleanup.
            await tunnel.remove_toxic(toxic)
            await tunnel.close()

        await self.do_cleanup(toxid, echod)

    async def test_limit_data(self):
        # Setup.
        net_conf, \
        i, \
        toxid, \
        toxid_addr, \
        client, \
        echod, \
        echo_dest = await self.do_setup()

        send_buf = b"1" * 90
        for toxi_stream in streams():
            # Open new tunnel.
            tunnel = await self.new_tunnel(echo_dest, client)
            tunneld = d_vals(toxid.tunnel_servs)[0]
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

        await self.do_cleanup(toxid, echod)

    async def test_reset_peer(self):
        # Setup.
        net_conf, \
        i, \
        toxid, \
        toxid_addr, \
        client, \
        echod, \
        echo_dest = await self.do_setup()

        for toxi_stream in streams():
            # Open new tunnel.
            tunnel = await self.new_tunnel(echo_dest, client)
            tunneld = d_vals(toxid.tunnel_servs)[0]
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

        await self.do_cleanup(toxid, echod)

    async def test_timeout(self):
        # Setup.
        net_conf, \
        i, \
        toxid, \
        toxid_addr, \
        client, \
        echod, \
        echo_dest = await self.do_setup()

        net_conf = dict_child({
            "recv_timeout": 1
        }, NET_CONF)

        for n, toxi_stream in enumerate(streams()):
            # Open new tunnel.
            tunnel = await self.new_tunnel(echo_dest, client)
            tunneld = d_vals(toxid.tunnel_servs)[0]
            up_sock = tunneld.upstream_pipe.sock

            # Add limit data toxic.
            toxic = toxi_stream.add_timeout(2000)
            await tunnel.new_toxic(toxic)
            pipe, _ = await tunnel.get_pipe(net_conf)

            await pipe.send(b'test')
            await asyncio.sleep(1)
            out = await pipe.recv()
            assert(out is None)

            await asyncio.sleep(1.5)
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

        await self.do_cleanup(toxid, echod)

    async def test_slicer(self):
        # Setup.
        net_conf, \
        i, \
        toxid, \
        toxid_addr, \
        client, \
        echod, \
        echo_dest = await self.do_setup()

        send_buf = b"123456890" * 100
        for toxi_stream in streams():
            # Open new tunnel.
            tunnel = await self.new_tunnel(echo_dest, client)

            # Add slicer toxic.
            toxic = toxi_stream.add_slicer()
            await tunnel.new_toxic(toxic)
            pipe, _ = await tunnel.get_pipe()
            await pipe.send(send_buf)
            await asyncio.sleep(1)

            # Receive sliced packets.
            recv_lens = []; recv_buf = b"" 
            while len(recv_buf) != len(send_buf):
                buf = await pipe.recv()
                recv_buf += buf
                recv_lens.append(len(buf))

            # Assert packet no and recv buffers.
            assert(recv_buf == send_buf)
            avg_recv = sum(recv_lens) / len(recv_lens)
            assert(avg_recv <= 150 and avg_recv >= 50)

            # Cleanup.
            await pipe.close()
            await tunnel.remove_toxic(toxic)
            await tunnel.close()

        await self.do_cleanup(toxid, echod)

    async def test_bandwidth_limit(self):
        # Setup.
        net_conf, \
        i, \
        toxid, \
        toxid_addr, \
        client, \
        echod, \
        echo_dest = await self.do_setup()

        bw_limit = 1; kb_send = 3; test_no = 3
        send_buf = b"1234567890" * 15000
        send_buf = send_buf[:1024 * kb_send]
        assert(len(send_buf) == 1024 * kb_send)
        for toxi_stream in streams():
            # Open new tunnel.
            tunnel = await self.new_tunnel(echo_dest, client)

            # Add bw data toxic.
            toxic = toxi_stream.add_bandwidth_limit(bw_limit)
            await tunnel.new_toxic(toxic)
            pipe, _ = await tunnel.get_pipe()
            readings = []
            for _ in range(0, test_no):
                start_time = time.time()
                await pipe.send(send_buf)

                recv_buf = b""
                while len(recv_buf) != len(send_buf):
                    recv_buf += await pipe.recv()

                end_time = time.time()
                duration = end_time - start_time
                readings.append(duration)

            # This is average to send 5 kbs.
            # Reducing the average by 5 is the average for 1 kb.
            # How closely does that match the bandwidth limit?
            avg_duration = sum(readings) / len(readings)
            avg_kb_rate = kb_send / avg_duration
            assert(avg_kb_rate <= bw_limit)
            assert(avg_kb_rate >= (bw_limit * 0.7))

            # Cleanup.
            await pipe.close()
            await tunnel.remove_toxic(toxic)
            await tunnel.close()

        await self.do_cleanup(toxid, echod)
            
    async def test_slow_close(self):
        # Setup.
        net_conf, \
        i, \
        toxid, \
        toxid_addr, \
        client, \
        echod, \
        echo_dest = await self.do_setup()

        test_time = 1500
        for n, toxi_stream in enumerate(streams()):
            # Open new tunnel.
            tunnel = await self.new_tunnel(echo_dest, client)
            tunneld = d_vals(toxid.tunnel_servs)[0]

            # Add limit data toxic.
            toxic = toxi_stream.add_slow_close(test_time)
            await tunnel.new_toxic(toxic)
            pipe, _ = await tunnel.get_pipe()

            # Should close after timeout.
            await pipe.send(b'test')
            await asyncio.sleep(1)

            start_time = time.time()
            if n == 0:
                ports = tunneld.servers[IP4][TCP]
                for port in ports:
                    client_pipe = ports[port]["127.0.0.1"].tcp_clients[0]
                    await client_pipe.close()
                    break
            else:        
                await tunneld.upstream_pipe.close()

            end_time = time.time()
            duration = end_time - start_time
            assert(duration * 1000 >= (test_time * 0.7))

            # Cleanup.
            await pipe.close()
            await tunnel.remove_toxic(toxic)
            await tunnel.close()

        await self.do_cleanup(toxid, echod)


if __name__ == '__main__':

    main()
