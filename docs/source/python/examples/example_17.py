from p2pd import *

TOXID_HOST = "127.0.0.1"
TOXID_PORT = 8867

async def example():
    # Start the Toxiproxy server.
    i = await Interface()
    toxid = ToxiMainServer([i])
    route = await i.route().bind(port=TOXID_PORT, ips=TOXID_HOST)
    await toxid.add_listener(TCP, route)
    #
    # Create a Toxiproxy client.
    # This just connects to the server above.
    toxid_addr = (TOXID_HOST, TOXID_PORT)
    client = await ToxiClient(toxid_addr).start()
    #
    # Create a new relay to an upstream.
    # The upstream location is set bellow.
    relay_dest = ("93.184.215.14", 80)
    tunnel = await client.new_tunnel(relay_dest)
    #
    # Add an upstream 'toxic' that adds latency to replies.
    toxic = ToxiToxic().upstream().add_latency(ms=2000, jitter=200)
    await tunnel.new_toxic(toxic)
    #
    # Get a pipe to the tunnel (you're the 'downstream.')
    # Send data down the tunnel to the upstream.
    pipe, tunnel_tup = await tunnel.get_pipe()
    await pipe.send(b"some malformed http req\r\n\r\n")
    #
    # ... response in 2 sec +/- jitter ms.
    # If you care to do a recv here...
    #
    # Cleanup everything gracefully.
    await pipe.close()
    await tunnel.close()
    await toxid.close()
    #
    # Give tasks time to finish..
    await asyncio.sleep(2)

if __name__ == '__main__':
    async_test(example)