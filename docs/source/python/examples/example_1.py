from p2pd import *

# Put your custom protocol code here.
async def msg_cb(msg, client_tup, pipe):
    # E.G. add a ping feature to your protocol.
    if b"PING" in msg:
        await pipe.send(b"PONG")

# Warning: startup is slow - be patient.
async def example():
    # Start our main node server.
    # The node implements your protocol.
    node = await start_p2p_node(
        # Set to true for port forwarding + pin holes.
        enable_upnp=False
    )
    node.add_msg_cb(msg_cb)
    #
    # Spawn a new pipe from a P2P con.
    # Connect to our own node server.
    pipe, success_type = await node.connect(node.addr_bytes)
    #
    # Test send / receive.
    msg = b"test send"
    await pipe.send(b"ECHO " + msg)
    out = await pipe.recv()
    #
    # Cleanup.
    assert(msg in out)
    await pipe.close()
    await node.close()

# Run the coroutine.
# Or await example() if in async REPL.
if __name__ == '__main__':
    async_test(example)