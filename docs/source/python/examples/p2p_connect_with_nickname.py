from p2pd import *

async def example():
    # Start a new P2P node.
    node = await P2PNode()
    pipe = await node.connect("unique.peer")