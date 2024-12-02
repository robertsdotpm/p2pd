from p2pd import *


import asyncio
import re

async def main():
    print("hello")
    

    netifaces = await init_p2pd()
    print(netifaces)
    
    
    nic = await Interface()
    print("after load nic")
    print(nic)
    # python "C:\projects\p2pd\tests\test_35.py"

"""
need to figure out a fix for event loop creation and running
the async_test and selector stuff sucks
"""
loop = asyncio.get_event_loop()
loop.run_until_complete(main())
 
