import random
import binascii
from p2pd import *

async def example():
    # Open default interface.
    # Get a route for the first AF supported.
    netifaces = await init_p2pd()
    i = await Interface(netifaces=netifaces).start()
    route = await i.route().bind()
    #
    # Open a UDP pipe to p2pd.net's STUN server.
    # Subscribe to all messages.
    pipe = (
        await pipe_open(
            UDP,
            await Address("p2pd.net", 34780, route).res(),
            route
        )
    ).subscribe()
    #
    # Build a STUN request and send it.
    msg_id = ''.join([str(random.randrange(10, 99)) for _ in range(16)])
    req_hex = "00010000" + msg_id
    req_buf = binascii.unhexlify(req_hex)
    await pipe.send(req_buf)
    #
    # Get the response.
    resp = await pipe.recv()
    await pipe.close()

if __name__ == '__main__':
    async_test(example)