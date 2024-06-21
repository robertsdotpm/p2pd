from p2pd import *


class TestP2PAddr(unittest.IsolatedAsyncioTestCase):
    async def test_p2p_addr(self):
        x = b"0,1-[0,8.8.8.8,192.168.21.200,33334,2,5,1]-0-kjCimIvudifJh7X"
        out = parse_peer_addr(x)
        print(out)
        self.assertTrue(len(out[IP4]))

    async def test_packing(self):
        node_id = b"123" * 10
        signal_offsets = [1, 2, 3]
        if_list = await load_interfaces()


        print(if_list)

        addr_buf = pack_peer_addr(
            node_id,
            if_list,
            signal_offsets
        )

        out = unpack_peer_addr(addr_buf)

if __name__ == '__main__':
    main()

