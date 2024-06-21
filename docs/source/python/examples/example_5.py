from p2pd import *

async def msg_cb(msg, client_tup, pipe):
    await pipe.send(msg, client_tup)

async def example():
    #
    # Start default interface and get the first route.
    # No AF for route use i.supported()[0] 
    i = await Interface().start()
    route = await i.route().bind() # Port 0 = any unused port.
    #
    # Start the server and use msg_cb to process messages.
    server = await pipe_open(TCP, route, msg_cb=msg_cb)
    #
    # Connect to the server.
    # Use the IP of the route and unused port for the destination.
    dest = Address(*server.sock.getsockname()[0:2])
    client = await pipe_open(TCP, route, dest)
    #
    # Send data to the server and check receipt.
    msg = b"test msg."
    await client.send(msg)
    out = await client.recv()
    assert(msg == out)
    #
    # Close both.
    await client.close()
    await server.close()

# From inside the async REPL.
if __name__ == '__main__':
    async_test(example)