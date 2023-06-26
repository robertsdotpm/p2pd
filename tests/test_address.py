from p2pd.test_init import *
from p2pd import Address, HOST_TYPE_IP, HOST_TYPE_DOMAIN
from p2pd import IP6, IP4
from p2pd import Interface

class TestIPRange(unittest.IsolatedAsyncioTestCase):
    async def test_domain_resolve(self):
        i = await Interface().start_local()
        r = i.route()
        a = await Address("www.google.com", 80, r).res()
        self.assertEqual(a.host_type, HOST_TYPE_DOMAIN)

    async def test_v6_resolve(self):
        i = await Interface().start_local()
        ip = "2402:1f00:8101:083f:0000:0000:0000:0001"
        r = i.route(IP6)
        a = await Address(ip, 80, r).res()
        self.assertEqual(a.host_type, HOST_TYPE_IP)
        self.assertTrue(a.is_public)

    async def test_v4_resolve(self):
        i = await Interface().start_local()
        r = i.route(IP4)
        ip = "192.168.0.1"
        a = await Address(ip, 80, r).res()
        self.assertEqual(a.host_type, HOST_TYPE_IP)
        self.assertTrue(a.is_private)

if __name__ == '__main__':
    main()