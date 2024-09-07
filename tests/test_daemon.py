from p2pd import *


asyncio.set_event_loop_policy(SelectorEventPolicy())
class TestDaemon(unittest.IsolatedAsyncioTestCase):

    async def test_daemon(self):
        server_port = 33200
        loopbacks = {
            IP4: "127.0.0.1",
            IP6: "::1"
        }

        at_least_one = False
        i = 0
        interface = await Interface()
        for af in interface.supported():
            log(f"Test daemon af = {af}")

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
            addrs = [route.nic(), loopbacks[af], "*"]

            # Test connect to link local.
            if af == IP6:
                addrs.append(route.link_local())

            addrs = [route.nic()]
            for addr in addrs:
                log(f"test daemon addr = {addr}")
                msg = b"hello world ay lmaoo"
                for proto in [UDP, TCP]:
                    log(f"test daemon proto = {proto}")
                    #print()
                    #print(proto)
                    #print(addr)

                    # Fresh route per server.
                    i += 1
                    echo_route = await interface.route(af).bind(ips=addr, port=server_port + i)
                    #print(echo_route)
                    #print(echo_route._bind_tups)

                    # Daemon instance.
                    echod = EchoServer()
                    await echod.add_listener(
                        proto,
                        echo_route
                    )

                    if addr == "*":
                        addr = "localhost"

                    dest = (addr, server_port + i)

                    # Spawn a pipe to the echo server.
                    test_route = await interface.route(af).bind(ips=addr)
                    pipe = await pipe_open(
                        proto,
                        dest,
                        test_route,
                    )
                    self.assertTrue(pipe is not None)

                    # Indicate to save all messages to a queue.
                    pipe.subscribe(SUB_ALL)

                    # Send message to server.
                    #print(dest.tup)
                    send_ret = await pipe.send(msg, dest)

                    # Receive data back.
                    data = await pipe.recv(SUB_ALL)
                    self.assertEqual(data, msg)

                    # Test accept() await.
                    # Send message from pipe to server's client pipe.
                    # Then manually call it's receive and check for receipt.
                    client_pipe = await pipe
                    self.assertTrue(client_pipe is not None)
                    client_pipe.subscribe(SUB_ALL)
                    await pipe.send(msg, dest)
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

        await asyncio.sleep(0.1)

if __name__ == '__main__':
    main()

"""
echo server tcp stream socket not being closed.
"""