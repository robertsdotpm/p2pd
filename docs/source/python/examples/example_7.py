from p2pd import *

async def example():
    #
    # Start default interface.
    # Don't bother resolving external addresses.
    i = await Interface().start()
    #
    # Echo server address.
    route = await i.route().bind()
    echo_dest = ("45.79.112.203", 4242)
    #
    # Open a connection to the echo server.
    pipe = await pipe_open(TCP, echo_dest, route)
    # No need to call pipe.subscribe(SUB_ALL).
    # This is done automatically if a destination is provided.
    # Call pipe.unsubscribe(SUB_ALL) to turn this off.
    #
    # Send data down the pipe.
    msg = b"do echo test"
    await pipe.send(msg + b"\r\n", echo_dest.tup)
    #
    # Receive data back.
    data = await pipe.recv(SUB_ALL, 4)
    assert(msg in data)
    #
    # Close the sockets.
    await pipe.close()

# Utility function to run an async function.
if __name__ == '__main__':
    async_test(example)