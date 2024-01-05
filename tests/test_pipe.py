"""
It turns out being able to successfully handle TCP close in server
protocol code is very important because otherwise you can't easily
write custom servers that handle cleanup for various client
data structures that may be made.

The bellow tests confirm that the regular TCP close sequence done
by 'well-behaving' clients (which involves a 4-way FIN ... ACK)
is supported. I've also written tests to check that RST works.
RST forcefully tears down a connection and the flag is usually set
during an error. You can also force it to be sent by toggling
the 'no-linger' timeout to 0 -- though this is considered bad practice.

I have confirmed that the appropriate packets are sent in Wireshark.
The below tests are working but I've only tested this on one OS
so far. Hopefully it works well on other OSes, too.
"""

from p2pd import *


class MinReader(asyncio.StreamReaderProtocol):
    def __init__(self, reader):
        self.close_set = False
        super().__init__(reader)

    def connection_made(self, transport):
        self.transport = transport
        super().connection_made(transport)

    def data_received(self, data):
        super().data_received(data)

    # Patch for stream reader protocol bug.
    def eof_received(self):
        reader = self._stream_reader
        if reader is not None:
            reader.feed_eof()

        return False

    def connection_lost(self, exc):
        # The socket has been closed
        self.close_set = True

async def create_server():
    reader = asyncio.StreamReader(limit=10000)

    # Make server to test close handler works.
    loop = asyncio.get_event_loop()
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind(('127.0.0.1', 0))
    mr = MinReader(reader)
    server = await loop.create_server(
        lambda: mr,
        sock=lsock
    )

    dest = ("127.0.0.1", lsock.getsockname()[1])
    return server, dest, mr

class TestPipe(unittest.IsolatedAsyncioTestCase):
    # Tests server can handle regular FIN sequence.
    async def test_graceful_close(self):
        # Run listen server.
        server, dest, mr = await create_server()

        # Create client socket.
        cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to server and close client sock.
        cs.connect(dest)
        cs.send(b"test")
        cs.shutdown(socket.SHUT_RDWR)
        cs.close()

        # Check connection_lost was called.
        await asyncio.sleep(3)
        assert(mr.close_set)

        # Cleanup.
        server.close()
        await server.wait_closed()

    # Tests that server can handle RSTs.
    async def test_ungraceful_close(self):
        # Run listen server.
        server, dest, mr = await create_server()

        # Create client socket.
        cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Disable TCPs regular graceful close mode.
        # This means an RST is sent instead of FIN.
        linger = struct.pack('ii', 1, 0)
        cs.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_LINGER,
            linger
        )
        
        # Connect to server and teardown connection.
        cs.connect(dest)
        cs.send(b"test")
        cs.close()

        # Check connection_lost was called.
        await asyncio.sleep(3)
        assert(mr.close_set)

        # Cleanup.
        server.close()
        await server.wait_closed()

if __name__ == '__main__':
    main()