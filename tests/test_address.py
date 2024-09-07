from p2pd import *


class TestIPRange(unittest.IsolatedAsyncioTestCase):
    async def test_domain_resolve(self):
        i = await Interface()
        r = i.route()
        a = ("www.google.com", 80)
        dest = Address("www.google.com", 80)
        await dest.res(r)
        assert(dest.IP4 is not None)


    async def test_v6_resolve(self):
        try:
            i = await Interface()
            dest = Address(
                "2402:1f00:8101:083f:0000:0000:0000:0001",
                80
            )
            await dest.res( i.route(IP6) )
            assert(dest.IP6 is not None)
        except:
            log_exception()

    async def test_v4_resolve(self):
        try:
            i = await Interface()
            dest = Address(
                "192.168.0.1",
                80
            )
            await dest.res( i.route(IP4) )
            assert(dest.IP4 is not None)
        except:
            log_exception()

if __name__ == '__main__':
    main()