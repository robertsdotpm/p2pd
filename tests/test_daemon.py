from p2pd import *


asyncio.set_event_loop_policy(SelectorEventPolicy())
class TestDaemon(unittest.IsolatedAsyncioTestCase):
    async def test_listen_all_interface_target(self):
        i = await Interface().start_local()
        i.rp[IP6].routes = []

        # Daemon instance.
        server_port = 10126
        proto = TCP
        echod = await EchoServer().listen_all(
            [i],
            [server_port],
            [proto]
        )

        await echod.close()

    async def test_bind_target(self):
        d = Daemon()
        i = await Interface().start_local()
        i.rp[IP6].routes = []

        p = 10233
        b = await Bind(i, i.supported()[0], port=p).bind(p)
        await d._listen(
            target=b,
            port=p,
            proto=TCP
        )

        await d.close()

    async def test_listen_specific(self):
        d = Daemon()
        i = await Interface().start_local()
        i.rp[IP6].routes = []

        p = 10233
        b = await Bind(i, i.supported()[0], port=p).bind(p)
        await d.listen_specific(
            targets=[[b, TCP]],
        )

        await d.close()

    async def test_daemon(self):
        server_port = 0
        loopbacks = {
            IP4: "127.0.0.1",
            IP6: "::1"
        }

        at_least_one = False
        for af in [IP4, IP6]:
            log(f"Test daemon af = {af}")
            try:
                interface = await Interface(af).start()
                at_least_one = True
            except Exception:
                """
                Skip unsupported AF types. Meaning they cannot use
                the Internet with that address family. Will ensure
                IP6 has at least one global IP and one link local.
                """
                continue

            """
            (1) Get first route for AF type.
            (2) Use in-built method and manually specify bind IP of '*'.
            (3) For IP4 this will bind to 0.0.0.0.
            (4) For IP6 this will bind to ::.
            (5) Will test IP4 NIC IPs, IP6 link locals / local host.
            """
            try:
                route = await interface.route(af)
            except:
                continue
            addrs = [route.nic(), loopbacks[af]]


            # Test connect to link local.
            if af == IP6:
                addrs.append(route.link_local())

            for addr in addrs:
                log(f"test daemon addr = {addr}")
                msg = b"hello world ay lmaoo"
                for proto in [UDP, TCP]:
                    log(f"test daemon proto = {proto}")

                    # Fresh route per server.
                    route = await interface.route(af).bind(ips=addr, port=server_port)

                    # Daemon instance.
                    echod = await EchoServer().listen_all(
                        [route],
                        [server_port],
                        [proto]
                    )
                    server_port = echod.get_listen_port()
                    dest = await Address(addr, server_port, route).res()

                    # Spawn a pipe to the echo server.
                    test_route = await interface.route(af).bind(ips=addr)
                    pipe = await pipe_open(
                        proto,
                        test_route,
                        dest
                    )
                    self.assertTrue(pipe is not None)

                    # Indicate to save all messages to a queue.
                    pipe.subscribe(SUB_ALL)

                    # Send message to server.
                    #print(dest.tup in pipe.stream.handle)
                    send_ret = await pipe.send(msg, dest.tup)

                    # Receive data back.
                    data = await pipe.recv(SUB_ALL)
                    self.assertEqual(data, msg)

                    # Test accept() await.
                    # Send message from pipe to server's client pipe.
                    # Then manually call it's receive and check for receipt.
                    client_pipe = await pipe
                    self.assertTrue(client_pipe is not None)
                    client_pipe.subscribe(SUB_ALL)
                    await pipe.send(msg, dest.tup)
                    data = await client_pipe.recv(SUB_ALL)
                    self.assertEqual(data, msg)

                    """
                    Making sure cleanup works correctly is very important
                    because if they restart a server program it will
                    most probably try listen to the same address and that
                    will throw an 'address already in use' error if the
                    socket wasn't cleaned up correctly. The code here
                    will fail if cleanup for these servers isn't correct.
                    """
                    if pipe is not None:
                        await pipe.close()
                    if echod is not None:
                        await echod.close()

        self.assertTrue(at_least_one)
        await asyncio.sleep(0.1)

if __name__ == '__main__':
    main()

"""
echo server tcp stream socket not being closed.
"""