from p2pd.test_init import *
from p2pd import IPRange, HOST_TYPE_IP, HOST_TYPE_DOMAIN
from p2pd import IP6, IP4, Route, Interface
from p2pd.net import VALID_AFS, ip_norm, TCP, UDP, Bind
from p2pd.echo_server import EchoServer
from p2pd.base_stream import pipe_open, SUB_ALL
from p2pd.address import Address
from p2pd.utils import what_exception
from p2pd.daemon import Daemon

asyncio.set_event_loop_policy(SelectorEventPolicy())
class TestPipe(unittest.IsolatedAsyncioTestCase):
    async def test_connection_close(self):
        reader = asyncio.StreamReader(limit=10000)
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

        # Make server to test close handler works.
        loop = asyncio.get_event_loop()
        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.bind(('127.0.0.1', 0))
        mr = MinReader(reader)
        server = await loop.create_server(
            lambda: mr,
            sock=lsock
        )

        # Connect to server and close pipe.
        dest = ("127.0.0.1", lsock.getsockname()[1])
        cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cs.connect(dest)
        cs.send(b"test")
        cs.close()
        await asyncio.sleep(3)
        assert(mr.close_set)
        server.close()


if __name__ == '__main__':
    main()

"""
echo server tcp stream socket not being closed.
"""