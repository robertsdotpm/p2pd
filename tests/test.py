import aiodns
from p2pd import *

async def do_something():

    resolver = aiodns.DNSResolver()


    result = await resolver.query("google.com", "A")
    print(result)

    return
    i = await Interface()


    dest = ("google.com", 80)


    #route = i.route(IP4)
    route = None
    addr = (*dest)
    pipe = await pipe_open(TCP, dest, route)

    print(pipe)
    print(pipe.sock)
    if pipe is not None:
        await pipe.close()

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