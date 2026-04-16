from p2pd import *

# Warning: this is very slow to start.
async def example():
    # Start our main node server.
    # The node implements your protocol.
    # Strategies used to make a P2P connection.
    # Note that P2P_RELAY enables TURN.
    strategies = [ P2P_DIRECT, P2P_REVERSE, P2P_PUNCH ]

    async with P2PNode(port=NODE_PORT + 50) as node:
        """
        Spawns a new pipe from a P2P connection.
        In this case it's connecting to our own node server.
        There will be no barriers to do this so this will just use
        a plain direct TCP connection / P2P_DIRECT.
        Feel free to experiment with how it works.
        """
        pipe = await node.connect(node.addr_bytes, strategies)
        async with pipe:
            pass  # Do some stuff on the pipe ...

if __name__ == '__main__':
    async_test(example)