from p2pd import (HOST_TYPE_DOMAIN, HOST_TYPE_IP, IP4, IP6, Address, Interface,
                  IPRange, Route)
from p2pd.ack_udp import ACKUDP, BaseACKProto
from p2pd.base_stream import SUB_ALL, BaseProto, pipe_open
from p2pd.net import NET_CONF, RUDP, UDP, ip_norm
from p2pd.test_init import *


class TestRUDP(unittest.IsolatedAsyncioTestCase):
    async def test_rudp(self):
        await init_p2pd()
        i = await Interface().start_local()
        af = i.supported()[0]
        port = 40000
        r = await i.route(af).bind(port)
        dest_tup = (r.nic(), port)
        dest = await Address(*dest_tup, r).res()
        pipe = (await pipe_open(
            route=r,
            proto=RUDP,
            dest=dest,
        )).subscribe(SUB_ALL)

        msg = b"test meow"
        task, event = await pipe.stream.ack_send(msg, dest_tup)
        await asyncio.wait_for(
            event.wait(),
            2,
        )
        out = await pipe.recv(SUB_ALL)
        self.assertEqual(out, msg)
        await pipe.close()

    async def test_is_unique(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        b = BaseProto(sock=s)
        d = b"ayy lmao"
        c = ("127.0.0.1", 1337)
        r = b.is_unique_msg(
            pipe=None,
            data=d,
            client_tup=c,
        )

        self.assertTrue(r)
        s.close()


if __name__ == '__main__':
    main()
