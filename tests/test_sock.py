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
        loop = asyncio.get_running_loop()
        i = await Interface().start_local()
        af = i.supported()[0]
        r = await i.route(af).bind(0)
        d = await Address("8.8.8.8", 53, r)
        s = await socket_factory(route=r, dest_addr=d, sock_type=TCP, conf=NET_CONF)
        con_task = asyncio.create_task(
            loop.sock_connect(
                s, 
                d.tup
            )
        )

        await asyncio.wait_for(con_task, 2)
        if s is not None:
            s.close()

    async def test_high_port_reuse(self):
        # Config for reuse.
        conf = copy.deepcopy(NET_CONF)
        conf["reuse_addr"] = True

        # Load default interface.
        i = await Interface().start_local()
        r = i.route()

        # Make a new socket bound to a high order port.
        high_sock, high_port = await get_high_port_socket(r)

        # Make a new socket that shares the same port.
        r = await i.route().bind(high_port)
        reuse_sock = await socket_factory(r, conf=conf)

        # Cleanup both socket handles.
        high_sock.close()
        reuse_sock.close()



if __name__ == '__main__':
    main()

"""
one of the nic ips is not working. why would this break the
stun code though?
"""