from p2pd.test_init import *

from p2pd import IP6, IP4
from p2pd.p2p_addr import parse_peer_addr

class TestP2PAddr(unittest.IsolatedAsyncioTestCase):
    async def test_p2p_addr(self):
        x = b"0,1-[0,8.8.8.8,192.168.21.200,33334,2,5,1]-0-kjCimIvudifJh7X"
        out = parse_peer_addr(x)
        print(out)
        self.assertTrue(len(out[IP4]))

if __name__ == '__main__':
    main()

