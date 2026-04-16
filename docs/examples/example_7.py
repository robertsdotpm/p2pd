from p2pd import *

async def example():
    # Start default interface.
    # Don't bother resolving external addresses.
    nic = await Interface()
    
    # Echo server address.
    route = await nic.route().bind()
    echo_dest = ("45.79.112.203", 4242)
    
    # Open a connection to the echo server.
    pipe = await pipe_open(TCP, echo_dest, route)
    async with pipe:
        # Send data down the pipe.
        msg = b"do echo test"
        await pipe.send(msg + b"\r\n", echo_dest)

        # Receive data back.
        data = await pipe.recv(SUB_ALL, 4)
        assert(msg in data)

# Utility function to run an async function.
if __name__ == '__main__':
    async_test(example)