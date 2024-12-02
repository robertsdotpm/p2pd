#from p2pd import *
#from p2pd.win_wmic import *


import asyncio
import re


async def main():
    print("hello")
    return



    netifaces = await init_p2pd()
    print(netifaces)
    return
    
    nic = await Interface()
    print("after load nic")
    print(nic)
    # python "C:\projects\p2pd\tests\test_35.py"

"""
need to figure out a fix for event loop creation and running
the async_test and selector stuff sucks

ip4 needs to be ip 
guid missing?

netsh interface ip show interfaces -- not found
    use wmic nic name, if
    
note to self: if too many zombie processes take up the executor pool
python cant open a new event loop so it blocks forever with get_event_loop
this is a bug that is fixed by restarting the comp
"""
loop = asyncio.get_event_loop()
print(loop)
loop.run_until_complete(main())
 
