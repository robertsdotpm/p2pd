from p2pd import *

async def example():
    async with P2PNode() as node:
        pipe = await node.connect("example.peer", strategies=[P2P_PUNCH])
        async with pipe:
            pass  # use pipe here