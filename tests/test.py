from p2pd.test_init import *
from p2pd import Interface

async def do_something():
    await init_p2pd()
    i = await Interface()
    print(i)

async_test(do_something)

"""
The repr causes the code to break on windows? Why is that?
get_running_loop
new_event_loop
get_event_loop
"""