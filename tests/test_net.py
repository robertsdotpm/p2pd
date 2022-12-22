import platform
from p2pd.test_init import *
from p2pd import IPRange, HOST_TYPE_IP, HOST_TYPE_DOMAIN
from p2pd import IP6, IP4, Route
from p2pd.net import *

class TestNet(unittest.IsolatedAsyncioTestCase):
    async def test_ip_norm(self):
        tests = [
            ["1.1.1.1%test", "1.1.1.1"],
            ["1.1.1.1/24", "1.1.1.1"],
            ["1.1.1.1%test/24", "1.1.1.1"],
            ["::", ("0000:" * 8)[:-1]],
            ["::%test/24", ("0000:" * 8)[:-1]],
            ["::", ("0000:" * 8)[:-1]],
            ["2402:1f00:8101:083f:0000:0000:0000:0001", "2402:1f00:8101:083f:0000:0000:0000:0001"]
        ]

        for src_ip, out_ip in tests:
            self.assertEqual(ip_norm(src_ip), out_ip)

    async def test_rand_link_local(self):
        out = ipv6_rand_link_local()
        ipaddress.IPv6Address(out)

    async def test_netmask_to_cidr(self):
        nm = "255.255.255.255"
        out = netmask_to_cidr(nm)
        self.assertEqual(32, out)

    async def test_toggle_host_bits(self):
        nm = "255.255.0.0"
        out = toggle_host_bits(nm, "192.168.0.0", toggle=1)
        self.assertEqual(out, "192.168.255.255")

    async def test_ip_from_last(self):
        # Last 255 IP is broadcast and can't be used.
        out = ip_from_last(2, "255.255.255.0", "192.168.21.0")
        self.assertEqual("192.168.21.253", out)
        out = ip_from_last(1, "255.255.255.0", "192.168.21.0")
        self.assertEqual("192.168.21.254", out)

    async def test_ipv6_rand_host(self):
        out = ipv6_rand_host("2402:1f00:8101:83f0::0000", 64)
        self.assertTrue("2402:1f00:8101:83f0" in out)
        x = ipv6_norm(out)

    async def test_gen_mac(self):
        m = generate_mac()
        b = mac_to_b(m)

    """
    TODO: 
    async def test_nt_net(self):
        if platform.system() == "Windows":
            out = await nt_ipconfig()
            print(out)

            out = await nt_route_print(desc=None)
            print(out)
    """



if __name__ == '__main__':
    main()