from p2pd.test_init import *
from p2pd import IPRange
from p2pd.net import BLACK_HOLE_IPS, ip_norm

class TestIPRange(unittest.IsolatedAsyncioTestCase):
    async def test_ip_range_iter(self):
        ipr = IPRange("192.168.0.0", cidr=16)

        # Test iterating the range.
        i = 0
        for x in ipr:
            i += 1
            if i >= 2:
                break

    async def test_single_v4_no_params(self):
        ip = "10.0.0.1"
        ipr = IPRange(ip)
        self.assertEqual(len(ipr), 1)
        self.assertEqual(str(ipr[0]), ip)
        self.assertEqual(ipr.cidr, 32)
        self.assertTrue(ipr.is_private)
        self.assertFalse(ipr.is_public)

    async def test_single_v4_addr_any_no_params(self):
        ip = "0.0.0.0"
        ipr = IPRange(ip)
        self.assertEqual(str(ipr[0]), ip)
        self.assertEqual(len(ipr), 1)
        self.assertTrue(ipr.is_public)
        self.assertFalse(ipr.is_private)

    async def test_single_v6_addr_any_no_params(self):
        ip = "::"
        ipr = IPRange(ip)
        self.assertEqual(str(ipr[0]), ip)
        self.assertEqual(len(ipr), 1)
        self.assertEqual(ipr.cidr, 128)

    async def test_single_v6_link_local(self):
        ip = "fe80::ae1f:6bff:fe94:531a"
        ipr = IPRange(ip)
        self.assertEqual(str(ipr[0]), ip)
        self.assertEqual(len(ipr), 1)
        self.assertEqual(ipr.cidr, 128)
        self.assertTrue(ipr.is_private)
        self.assertFalse(ipr.is_public)

    async def test_single_v4_broadcast(self):
        ip = "255.255.255.255"  
        ipr = IPRange(ip)
        self.assertEqual(str(ipr[0]), ip)
        self.assertEqual(len(ipr), 1)
        self.assertEqual(ipr.cidr, 32)
        self.assertTrue(ipr.is_private)
        self.assertFalse(ipr.is_public)

    async def test_block_v6_public(self):
        ip = "2402:1f00:8101:83f::"  
        cidr = 64
        ipr = IPRange(ip, netmask=None, cidr=cidr)
        self.assertEqual(ipr.host_no, (2 ** 64) - 1)

        # First host in that block.
        self.assertEqual(str(ipr[0]), "2402:1f00:8101:83f::1")
        self.assertEqual(ipr.host_no, 18446744073709551615)

        # Last address in range -- all 1s set.
        self.assertEqual(str(ipr[-1]), "2402:1f00:8101:83f:ffff:ffff:ffff:ffff")

        # First address in range -- the value 1 store in 64 bits.
        self.assertEqual(str(ipr[0]), "2402:1f00:8101:83f::1")
        self.assertEqual(str(ipr[1]), "2402:1f00:8101:83f::2")

        # Test > sys.maxsize = memory addr overflow.
        # Len is expected to overflow.
        ip = "2402:1f00:8101::"
        cidr = 48
        ipr = IPRange(ip, netmask=None, cidr=cidr)
        self.assertEqual(ipr.host_no, (2 ** 80) - 1)

        # include 0 in range = -1, start counting from 0 = -1 so -2
        self.assertEqual(str(ipr[(2 ** 80) - 2]), "2402:1f00:8101:ffff:ffff:ffff:ffff:ffff")
        self.assertTrue(ipr.is_public)
        self.assertFalse(ipr.is_private)

    async def test_block_v4_public(self):
        ipr = IPRange("8.8.8.0", cidr=24)
        self.assertEqual(str(ipr[0]), "8.8.8.1")
        ipr = IPRange("8.8.8.4", cidr=24)
        self.assertEqual(str(ipr[-1]), "8.8.8.255")
        self.assertEqual(str(ipr[256]), "8.8.8.1")

    async def test_loopback_ips(self):
        v4_lb = "127.0.0.1"
        v6_lb = "::1"
        ipr = IPRange(v4_lb)
        self.assertEqual(len(ipr), 1)
        self.assertEqual(str(ipr[0]), v4_lb)
        self.assertEqual(str(ipr[4]), v4_lb)
        ipr = IPRange(v6_lb)
        self.assertEqual(len(ipr), 1)
        self.assertEqual(str(ipr[0]), v6_lb)
        self.assertEqual(str(ipr[3]), v6_lb)

    async def test_black_hole_ips(self):
        for ip in BLACK_HOLE_IPS.values():
            ipr = IPRange(ip)
            self.assertTrue(ipr.is_public)
            self.assertFalse(ipr.is_private)
            self.assertEqual(ip_norm(str(ipr[0])), ip)

    async def test_misc_ipr(self):
        ipr = IPRange("192.168.0.0", netmask="255.255.0.0")
        n = 0
        for needle in reversed(ipr):
            n += 1
            if n >= 2:
                break

        # Test host add works.
        ipr_a = IPRange("192.168.0.0", netmask="255.255.0.0")
        ipr_b = IPRange("192.169.0.4", netmask="255.255.0.0")
        ipr_c = IPRange("192.168.0.4", netmask="255.255.0.0")
        self.assertEqual(ipr_a + ipr_b, ipr_c)
        self.assertEqual(ipr_a + 4, ipr_c)

        # Test host sub works.
        ipr_d = IPRange("192.168.255.252", netmask="255.255.0.0")
        self.assertEqual(ipr_a - ipr_b, ipr_d)
        self.assertEqual(ipr_a - 4, ipr_d)

        # Get items.
        ipr_z = IPRange("192.168.0.3")
        ipr_y = IPRange("192.168.0.4")
        ipr_x = ipr_a[3]
        self.assertEqual(ipr_x, ipr_y)
        self.assertTrue(ipr_y > ipr_z)
        self.assertTrue(ipr_z < ipr_y)

        # You can use tuples to fetch a list of sub objects.
        ipr_list = ipr_a[(0, 1, 2)]
        hey_list = [
            IPRange("192.168.0.1"),
            IPRange("192.168.0.2"),
            IPRange("192.168.0.3"),
        ]
        self.assertEqual(ipr_list, hey_list)

if __name__ == '__main__':
    main()