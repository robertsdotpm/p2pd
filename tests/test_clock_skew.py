from p2pd import *


class TestClockSkew(unittest.IsolatedAsyncioTestCase):
    async def test_get_ntp_pool_ntp(self):
        i = await Interface()
        ntp = None

        for _ in range(0, 5):
            server = random.choice(NTP_SERVERS)
            ntp = await get_ntp(i, server=server)
            if ntp:
                break

        self.assertTrue(ntp)

    async def test_get_clock_skew(self):
        i = await Interface()
        sys_clock = await SysClock(i).start()
        self.assertTrue(sys_clock.clock_skew)

if __name__ == '__main__':
    main()