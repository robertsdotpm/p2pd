from p2pd import *


async def example():
    # TURN server config.
    dest = ("turn1.p2pd.net", 3478)
    auth = ("", "")

    # Each interface has a different external IP.
    # Imagine these are two different computers.
    a_nic = await Interface("enp0s25")
    b_nic = await Interface("wlx00c0cab5760d")

    # Start TURN clients.
    a_client = await TURNClient(IP4, dest, a_nic, auth, realm=None)
    b_client = await TURNClient(IP4, dest, b_nic, auth, realm=None)

    # In practice you will have to exchange these tups via your protocol.
    # I use MQTT for doing that. See diagram steps (1)(3).
    a_addr, a_relay = await a_client.get_tups()
    b_addr, b_relay = await b_client.get_tups()

    # White list peers for sending to relay address.
    # See diagram steps (2)(4).
    await a_client.accept_peer(b_addr, b_relay)
    await b_client.accept_peer(a_addr, a_relay)

    # Send a message to Bob at their relay address.
    # See middle of TURN relay diagram.
    buf = b"hello bob"
    for _ in range(0, 3):
        await a_client.send(buf)
    
    # Get msg from Alice from the TURN server.
    # See middle of TURN relay diagram.
    msg = await b_client.recv()
    assert(msg == buf)

    # Tell server to close resources for our client.
    await a_client.close()
    await b_client.close()



if __name__ == '__main__':
    async_test(example)