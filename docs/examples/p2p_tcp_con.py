from p2pd import *

strategies = [P2P_DIRECT, P2P_REVERSE, P2P_PUNCH]
async def example():
    node = await P2PNode()
    pipe = await node.connect("example.peer", strategies=strategies)
    await pipe.send(b"Hello, world!")
    buf = await pipe.recv()
    await node.close()