from p2pd import *

import asyncio


class TestEventLoops(unittest.IsolatedAsyncioTestCase):
    async def test_event_loops_a(self):
        running_loop = asyncio.get_running_loop()
        #new_loop = get_loop()

        try:
            new_loop = asyncio.get_running_loop()
        except:
            #uvloop.install()
            new_loop = get_loop(loop)
            
        print(running_loop)
        print(new_loop)
        

if __name__ == '__main__':
    main()