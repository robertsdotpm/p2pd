from p2pd.test_init import *
from p2pd.address import *
from p2pd.net import *
from p2pd.interface import *
from p2pd.stun_client import *
import socket
class TestSock(unittest.IsolatedAsyncioTestCase):
    async def test_reuse_port(self):
        s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except:
            pass
        s1.bind(('', 0))
        #s1.connect(("www.google.com", 80))

        port = s1.getsockname()[1]
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except:
            pass
        s2.bind(('', port))
        #s2.connect(("www.google.com", 80))

        s1.close()
        s2.close()

    async def test_socket_factory_connect(self):
        await init_p2pd()
        loop = asyncio.get_event_loop()
        i = await Interface().start_local()
        af = i.supported()[0]
        r = await i.route(af).bind()
        d = await Address("google.com", 80, r, TCP).res()
        s = await socket_factory(r, dest_addr=d, sock_type=TCP)
        await loop.sock_connect(
            s, 
            d.tup
        )

        if s is not None:
            s.close()



if __name__ == '__main__':
    main()

"""
one of the nic ips is not working. why would this break the
stun code though?
"""