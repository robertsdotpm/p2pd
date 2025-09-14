import asyncio
from p2pd import *

"""
Demonstrates that change attribute replies through STUN RFC 5389 aren't supported.
"""
async def main():
    nic = await Interface()

    # Google STUN server
    dest = ("74.125.192.127", 19302)
    route = nic.route(IP4)
    pipe = await pipe_open(UDP, route=route)
    stun_client = STUNClient(
        af=pipe.route.af,
        dest=dest,
        nic=nic,
        proto=UDP,
        mode=RFC5389
    )

    print(pipe, pipe.stream)

    reply_addr = (dest[0], 5349) # IDK the reply port tbh, either way -- it wont work.
    reply = await get_stun_reply(
        stun_client.mode,
        stun_client.dest,
        reply_addr,
        pipe,
        [[STUNAttrs.ChangeRequest, b"\0\0\0\1"]]
    )



    print(reply)

asyncio.run(main())