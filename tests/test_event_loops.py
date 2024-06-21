from p2pd import *

import asyncio


class TestEventLoops(unittest.IsolatedAsyncioTestCase):
    async def test_event_loops_a(self):
        running_loop = asyncio.get_event_loop()

                

if __name__ == '__main__':
    main()