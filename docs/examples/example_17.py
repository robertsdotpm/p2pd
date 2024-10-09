from p2pd import *

TOXID_HOST = LOCALHOST_LOOKUP
TOXID_PORT = 8867

async def example():
    # Start the Toxiproxy server.
    nic = await Interface()
    toxid = ToxiMainServer([nic])
    await toxid.listen_loopback(TCP, TOXID_PORT, nic)

    # Create a Toxiproxy client.
    # This just connects to the server above.
    af = nic.supported()[0]
    toxid_addr = (TOXID_HOST[af], TOXID_PORT)
    client_route = await nic.route(af).bind()
    client = await ToxiClient(toxid_addr, client_route)
    
    # Create a new relay to an upstream.
    # The upstream location is set bellow.
    # Example.com
    relay_dest = ("www.example.com", 80)
    tunnel = await client.new_tunnel(relay_dest)
    
    # Add an upstream 'toxic' that adds latency to replies.
    toxic = ToxiToxic().upstream().add_latency(ms=2000, jitter=200)
    await tunnel.new_toxic(toxic)
    
    # Get a pipe to the tunnel (you're the 'downstream.')
    # Send data down the tunnel to the upstream.
    pipe, tunnel_tup = await tunnel.get_pipe()
    await pipe.send(b"some malformed http req\r\n\r\n")
    
    # ... response in 2 sec +/- jitter ms.
    # If you care to do a recv here...
    
    # Cleanup everything gracefully.
    await pipe.close()
    await tunnel.close()
    await toxid.close()
    
    # Give tasks time to finish..
    await asyncio.sleep(2)

if __name__ == '__main__':
    async_test(example)