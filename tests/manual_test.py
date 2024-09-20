"""
Theories:
    - parse peer addr doesn't append them back in the right order?

    - assuming af availability when one doesnt exist leads to invalid offsets. but i dont think thats the only issue as both afs support ipv4
"""

import aiodns
from p2pd import *



def check_if_offsets(addr):
    for af in VALID_AFS:
        for i in range(0, len(addr[af])):
            if i not in addr[af]:
                continue

            assert(addr[af][i]["if_index"] == i)
            #print(f"{addr[af][i]} {i}")


async def do_something():
    #print(x)
    #print(y)

    global x
    global y
    x = parse_peer_addr(x["bytes"])
    y = parse_peer_addr(y["bytes"])



    #print(a)

    #return
    for af in [IP4]:

        pass

    # Make sure iter hasn't corrupted if offsets.
    check_if_offsets(x)
    check_if_offsets(y)

    #print(x)
    #print(y)

async_test(do_something)

"""
The repr causes the code to break on windows? Why is that?
get_running_loop
new_event_loop
get_event_loop
create task

im seeing packet drops to stun servers with ipv6 udp on my network
im not sure what the cause is yet
"""