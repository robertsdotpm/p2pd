import hashlib
import secrets
from p2pd import *

COMPUTER_A_NAME = ["computer_a", ".node"]

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
    node = await start_p2p_node(
        # Used to create the accounts that can modify COMPUTER_A_NAME!
        # Save your seed value to reuse it! Otherwise names are lost.
        seed=hashlib.sha3_256(b"computer a unique password"),
        #
        # Set to true for port forwarding + pin holes.
        enable_upnp=False,
        #
        # Make sure node server uses different port.
        port=NODE_PORT + 50 + 1
        
    )
    node.add_msg_cb(msg_cb)
    #
    # Register a human readable name for this peer.
    # NOTE: for demo only -- use your own unique name!
    await node.register(COMPUTER_A_NAME)
    #
    return node

async def computer_b():
    # Start our main node server.
    # The node implements your protocol.
    node = await start_p2p_node(
        # Used to create the accounts that can modify computer b's names!
        # Save your seed value to reuse it! Otherwise names are lost.
        seed=secrets.token_bytes(24),
        #
        # Set to true for port forwarding + pin holes.
        enable_upnp=False,
        #
        # Make sure node server uses different port
        # to computer_a.
        port=NODE_PORT + 50 + 2
    )
    #
    # Spawn a new pipe from a P2P con.
    # Connect to their node server.
    pipe, success_type = await node.connect(COMPUTER_A_NAME)
    #
    # Test send / receive.
    msg = b"test send"
    await pipe.send(b"ECHO " + msg)
    out = await pipe.recv()
    #
    # Cleanup.
    assert(msg in out)
    await pipe.close()
    #
    return node
    
# Warning: startup is slow - be patient.
async def example():
    """
    (1) Computer A starts a node server and uses 'IRCDNS'
    to store its address at a given name.
    """
    node_a = await computer_a()
    #
    #
    """
    (2) Computer B starts a node server and uses 'IRCDNS'
    to lookup the p2p address of computer a to connect to it.
    """
    node_b = await computer_b()
    #
    #
    # Cleanup / shut down node servers.
    await node_a.close()
    await node_b.close()

# Run the coroutine.
# Or await example() if in async REPL.
if __name__ == '__main__':
    async_test(example)