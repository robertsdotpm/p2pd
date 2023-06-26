from p2pd import *

async def example():
    #
    # Start default interface.
    # Don't bother resolving external addresses.
    i = await Interface().start()
    #
    # Echo server address.
    route = await i.route().bind()
    echo_dest = await Address("tcpbin.com", 4242, route).res()
    #
    # Open a connection to the echo server.
    pipe = await pipe_open(TCP, route, echo_dest)
    #
    # Create a new queue for a related subscription.
    # Subscription = [b"msg pattern regex", b"address pattern regex"]
    # SUB_ALL = [b"", b""] meaning 'any message', 'from any address.'
    pipe.subscribe(SUB_ALL)
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