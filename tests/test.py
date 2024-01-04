from p2pd import *

async def do_something():
    await init_p2pd()
    i = await Interface()
    print(i)
    loop = asyncio.get_event_loop()
    print(loop)

async_test(do_something)

"""
The repr causes the code to break on windows? Why is that?
get_running_loop
new_event_loop
get_event_loop
ensure_future or create task

im seeing packet drops to stun servers with ipv6 udp on my network
im not sure what the cause is yet
"""