from p2pd import *

async def example():
    node = await P2PNode()
    peer_name = await node.nickname("unique") # -> unique.tld 
    print(peer_name)