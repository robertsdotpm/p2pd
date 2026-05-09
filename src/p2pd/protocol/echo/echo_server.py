"""Simple echo server used for connectivity testing."""
import asyncio
from aionetiface import (
    Daemon, async_wrap_errors, fstr, get_running_loop, Interface, TCP, IP4,
)


class EchoServer(Daemon):
    """Simple echo server daemon that reflects all received messages back to senders."""

    def __init__(self):
        super().__init__()

    async def msg_cb(self, msg, client_tup, pipe):
        """Echo msg back to client_tup on the same pipe."""
        await async_wrap_errors(pipe.send(msg, client_tup))


if __name__ == "__main__":  # pragma: no cover
    print("See tests/test_daemon.py for code that uses this.")

    class EchoProtocol(asyncio.Protocol):
        """asyncio.Protocol that logs connections and echoes all received data."""

        def connection_made(self, transport):
            """Store the transport and log the incoming connection address."""
            self.transport = transport
            print(transport)
            print(transport.get_extra_info("socket"))
            addr = transport.get_extra_info("peername")
            print(fstr("Connection from {0}", (addr,)))

        def data_received(self, data):
            """Log and echo back the received data."""
            message = data.decode()
            addr = self.transport.get_extra_info("peername")
            print(
                fstr(
                    "Received {0} from {1}",
                    (
                        message,
                        addr,
                    ),
                )
            )
            # Echo back
            self.transport.write(data)

        def connection_lost(self, exc):
            """Log the closed connection address."""
            addr = self.transport.get_extra_info("peername")
            print(fstr("Connection closed from {0}", (addr,)))

    async def echo_main():
        """Start a standalone TCP echo server on 127.0.0.1:3000 for manual testing."""
        loop = get_running_loop()
        server = await loop.create_server(lambda: EchoProtocol(), "127.0.0.1", 3000)

        print("Echo server listening on 127.0.0.1:3000")
        async with server:
            await server.serve_forever()

        nic = await Interface()
        echo_route = await nic.route(IP4).bind(ips="localhost", port=3000)
        # print(echo_route)
        # print(echo_route._bind_tups)

        # Daemon instance.
        echod = EchoServer()
        await echod.add_listener(TCP, echo_route)

        while True:
            await asyncio.sleep(1)

    asyncio.run(echo_main())
