from p2pd.test_init import *
import random
from p2pd.clock_skew import *
from p2pd.settings import *

class TestClockSkew(unittest.IsolatedAsyncioTestCase):
    async def test_get_ntp_pool_ntp(self):
        i = await Interface().start_local()
        ntp = None

        for _ in range(0, 5):
            server = random.choice(NTP_SERVERS)
            ntp = await get_ntp(i, server=server[0])
            if ntp:
                break

        self.assertTrue(ntp)

    async def test_get_clock_skew(self):
        i = await Interface().start_local()
        sys_clock = await SysClock(i).start()
        self.assertTrue(sys_clock.clock_skew)

if __name__ == '__main__':
    main()