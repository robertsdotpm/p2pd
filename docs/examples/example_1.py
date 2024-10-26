from p2pd import *

COMPUTER_A_NAME = "computer_a"

# Put your custom protocol code here.
async def msg_cb(msg, client_tup, pipe):
    # E.G. add a ping feature to your protocol.
    if b"PING" in msg:
        await pipe.send(b"PONG")

# Computer a and b code can run on different
# computers -- for demo they're just on the same.
async def computer_a():
    # Start our main node server.
    # The node implements your protocol.
    node = P2PNode(
        # Make sure node server uses different port.
        port=NODE_PORT + 50 + 1
    )
    node.add_msg_cb(msg_cb)
    
    # Start the node listening.
    await node.start()
    
    # Register a human readable name for this peer.
    # NOTE: for demo only -- use your own unique name!
    # NOTE: it returns the name + success TLD.
    node_a_url = await node.nickname(COMPUTER_A_NAME)
    return node_a_url, node

async def computer_b(node_a_url):
    # Start our main node server.
    # The node implements your protocol.
    node = P2PNode(
        # Make sure node server uses different port.
        port=NODE_PORT + 50 + 2
    )

    # Start the node listening.
    await node.start()
    
    # Spawn a new pipe from a P2P con.
    # Connect to their node server.
    pipe = await node.connect(node_a_url)
    
    # Test send / receive.
    msg = b"test send"
    await pipe.send(b"ECHO " + msg)
    out = await pipe.recv()
    
    # Cleanup.
    assert(msg in out)
    await pipe.close()
    return node
    
# Warning: startup is slow - be patient.
async def example():
    """
    (1) Computer A starts a node server and uses 'PNP'
    to store its address at a given name.
    """
    node_a_url, node_a = await computer_a()

    """
    (2) Computer B starts a node server and uses 'PNP'
    to lookup the p2p address of computer a to connect to it.
    """
    node_b = await computer_b(node_a_url)

    # Cleanup / shut down node servers.
    await node_a.close()
    await node_b.close()

# Run the coroutine.
# Or await example() if in async REPL.
if __name__ == '__main__':
    async_test(example)