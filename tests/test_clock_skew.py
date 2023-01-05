from p2pd.test_init import *
import socket
from p2pd.clock_skew import *

class TestClockSkew(unittest.IsolatedAsyncioTestCase):
    async def test_get_ntp_pool_ntp(self):
        await init_p2pd()
        i = await Interface().start_local()
        ntp = await get_ntp(i, server="time.google.com")
        self.assertTrue(ntp)

    async def test_get_clock_skew(self):
        await init_p2pd()
        i = await Interface().start_local()
        sys_clock = await SysClock(i).start()
        self.assertTrue(sys_clock.clock_skew)

if __name__ == '__main__':
    main()