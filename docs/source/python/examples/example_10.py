from p2pd import *

TURN_OFFSET = 0

async def example():
    # Network interface details.
    n = await init_p2pd()
    i = await Interface(netifaces=n).start()
    r = await i.route().bind()
    #
    # Address of a TURN server.
    dest = await Address(
        TURN_SERVERS[TURN_OFFSET]["host"],
        TURN_SERVERS[TURN_OFFSET]["port"],
        r
    ).res()
    #
    # Sync message callback -- do something here if you like.
    # Can be async too.
    msg_cb = lambda msg, client_tup, pipe: print(msg)
    #
    # Implement the TURN protocol for UDP send / recv.
    client = TURNClient(
        turn_addr=dest,
        turn_user=TURN_SERVERS[TURN_OFFSET]["user"],
        turn_pw=TURN_SERVERS[TURN_OFFSET]["pass"],
        turn_realm=TURN_SERVERS[TURN_OFFSET]["realm"],
        route=r,
        msg_cb=msg_cb
    )
    #
    # Wait for authentication and relay address allocation.
    await async_wrap_errors(
        client.start()
    )
    client.subscribe(SUB_ALL)
    #
    # Give this to a client to send to ourselves.
    our_relay_tup = await client.relay_tup_future
    our_client_tup = await client.client_tup_future
    #
    """
    To receive messages back from a given client you will have
    to call: await client.accept_peer(their_client_tup, their_relay_tup) which implies you have your own way to
    exchange these details between clients (I use MQTT.)
    """
    # Cleanup.
    await client.close()

if __name__ == '__main__':
    async_test(example)