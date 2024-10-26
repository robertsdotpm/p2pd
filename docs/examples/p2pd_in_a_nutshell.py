from p2pd import *

# Put your custom protocol code here.
async def msg_cb(msg, client_tup, pipe):
    # E.G. add a ping feature to your protocol.
    if b"PING" in msg:
        await pipe.send(b"PONG", client_tup)

async def example():
    # Start a new P2P node with your protocol.
    node = await P2PNode()
    node.add_msg_cb(msg_cb)