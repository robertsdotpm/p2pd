from p2pd import *

strategies = [P2P_DIRECT, P2P_REVERSE, P2P_PUNCH]


async def example():
    async with P2PNode() as node:
        pipe = await node.connect("example.peer", strategies=strategies)
        async with pipe:
            await pipe.send(b"Hello, world!")
            buf = await pipe.recv()
