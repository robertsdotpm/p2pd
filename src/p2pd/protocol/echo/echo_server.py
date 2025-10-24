from ...net.daemon import *

class EchoServer(Daemon):
    def __init__(self):
        super().__init__()

    async def msg_cb(self, msg, client_tup, pipe):
        await async_wrap_errors(
            pipe.send(msg, client_tup)
        )

if __name__ == "__main__": # pragma: no cover
    print("See tests/test_daemon.py for code that uses this.")

    class EchoProtocol(asyncio.Protocol):
        def connection_made(self, transport):
            self.transport = transport
            print(transport)
            print(transport.get_extra_info("socket"))
            addr = transport.get_extra_info('peername')
            print(f"Connection from {addr}")

        def data_received(self, data):
            message = data.decode()
            addr = self.transport.get_extra_info('peername')
            print(f"Received {message!r} from {addr}")
            # Echo back
            self.transport.write(data)

        def connection_lost(self, exc):
            addr = self.transport.get_extra_info('peername')
            print(f"Connection closed from {addr}")

    async def echo_main():
        from p2pd.net.net import IP4, TCP
        from p2pd.nic.interface import Interface

        loop = asyncio.get_running_loop()
        server = await loop.create_server(
            lambda: EchoProtocol(),
            '127.0.0.1', 3000
        )

        print("Echo server listening on 127.0.0.1:3000")
        async with server:
            await server.serve_forever()



        nic = await Interface()
        echo_route = await nic.route(IP4).bind(ips="localhost", port=3000)
        #print(echo_route)
        #print(echo_route._bind_tups)

        # Daemon instance.
        echod = EchoServer()
        await echod.add_listener(
            TCP,
            echo_route
        )

        while 1:
            await asyncio.sleep(1)

    asyncio.run(echo_main())