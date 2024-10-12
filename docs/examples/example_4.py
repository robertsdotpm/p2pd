from p2pd import *

async def example():
    # Load default interface.
    nic = await Interface()
    
    # Get a route to use for sockets.
    # This will give you a copy of the first route for that address family.
    # Routes belong to an interface and include a reference to it.
    route = await nic.route(IP4).bind()
    
    # Lookup Google.com's IP address -- specify a specific address family.
    # Most websites support IPv4 but not always IPv6.
    # Interface is needed to resolve some specialty edge-cases.
    dest = ("8.8.8.8", 53)
    
    # Now open a TCP connection to that the destination.
    pipe = await pipe_open(TCP, dest, route)
    
    # Send it a malformed HTTP request.
    buf = b"Test\r\n\r\n"
    await pipe.send(buf)
    
    # Wait for any message response.
    out = await pipe.recv(timeout=3)
    print(out)
    
    # Cleanup.
    await pipe.close()

if __name__ == '__main__':
    async_test(example)