from p2pd import *


class TestP2PAddr(unittest.IsolatedAsyncioTestCase):
    async def test_p2p_addr(self):
        x = b"0,2,3,1-[1,0,8.8.8.8,192.168.21.3,10001,1,2,1]-0-93e9d6f7e7791ea06544557a2-c88e78bafc408223a97b560ea94f1bb4d5fc58a5705a41a2a94d54466d552816"
        out = parse_peer_addr(x)
        print(out)
        self.assertTrue(len(out[IP4]))

if __name__ == '__main__':
    main()

