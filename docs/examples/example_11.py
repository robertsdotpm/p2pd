from p2pd import *

# Warning: this is very slow to start.
async def example():
    # Start our main node server.
    # The node implements your protocol.
    node = P2PNode(
        # Make sure node server uses different port.
        port=NODE_PORT + 50
    )
    
    # Start node listening.
    await node.start()
    
    # Strategies used to make a P2P connection.
    # Note that P2P_RELAY enables TURN.
    # (Coturn doesn't support self relay so removed.)
    strategies = [ P2P_DIRECT, P2P_REVERSE, P2P_PUNCH ]
    
    """
    Spawns a new pipe from a P2P connection.
    In this case it's connecting to our own node server.
    There will be no barriers to do this so this will just use
    a plain direct TCP connection / P2P_DIRECT.
    Feel free to experiment with how it works.
    """
    pipe = await node.connect(node.addr_bytes, strategies)
    
    # Do some stuff on the pipe ...
    # Cleanup.
    await pipe.close()
    await node.close()

if __name__ == '__main__':
    async_test(example)