from p2pd import *

async def example():
    node = await P2PNode()
    pipe = await node.connect("example.peer", strategies=[P2P_RELAY])
    await node.close()