from p2pd import *


async def get_turn_client(af, interface, turn_offset):
    # Get a route for this interface.
    route = await interface.route(af).bind()
    try:
        dest = await Address(
            to_s(TURN_SERVERS[turn_offset]["host"]),
            TURN_SERVERS[turn_offset]["port"],
            route
        ).res()
    except:
        ip = TURN_SERVERS[turn_offset][IP4] or TURN_SERVERS[turn_offset][IP6] 
        dest = await Address(
            ip,
            TURN_SERVERS[turn_offset]["port"],
            route
        ).res()

    # Implement the TURN protocol for UDP send / recv.
    client = TURNClient(
        turn_addr=dest,
        turn_user=TURN_SERVERS[turn_offset]["user"],
        turn_pw=TURN_SERVERS[turn_offset]["pass"],
        turn_realm=TURN_SERVERS[turn_offset]["realm"],
        route=route
    )

    # Enable blank UDP headers.
    #client.toggle_blank_rudp_headers(True)

    # Wait for authentication and relay address allocation.
    await async_wrap_errors(
        client.start(),
        timeout=10
    )

    # Wait for the client to be ready.
    await client.client_tup_future
    await client.relay_tup_future
    return client

asyncio.set_event_loop_policy(SelectorEventPolicy())
class TestTurn(unittest.IsolatedAsyncioTestCase):
    async def test_turn_duel_ifs(self):
        # Offset of turn server to use.
        turn_offset = 2

        # Load interface list.
        netifaces = await init_p2pd()
        ifs, af = await duel_if_setup(netifaces)
        assert(len(ifs) == 2)
        if af is None:
            return

        # Will store the turn clients.
        turn_clients = []
        relay_tup = None
        for interface in ifs:
            # Get turn client.
            client = await get_turn_client(
                af,
                interface,
                turn_offset
            )

            # Save to list of clients.
            turn_clients.append(client)

        # Each turn client white lists the others external IP.
        # Thereby allowing msgs from that interface through.
        for if_index in range(0, len(ifs)):
            # Sending interface and it's external IP
            interface = ifs[(if_index + 1) % 2]
            route = await interface.route(af).bind()
            peer_tup = (route.ext(), 0)

            # Accept the other interfaces external IP.
            src_turn = turn_clients[if_index]
            dest_turn = turn_clients[(if_index + 1) % 2]
            relay_tup = await dest_turn.relay_tup_future
            await src_turn.accept_peer(peer_tup, relay_tup)

        # Test message receipt for both clients.
        msg = b"hello, world!"
        for if_index in range(0, len(ifs)):
            # Perspective is this if to that turn client.
            # The turn client is on another interface.
            interface = ifs[if_index]
            turn_client = turn_clients[(if_index + 1) % 2]

            # Send data to the relay endpoint.
            for i in range(0, 3):
                await turn_client.send(msg)

            # Recv data back.
            out = await turn_clients[if_index].recv(SUB_ALL, 2)
            assert(msg in out)

        # Cleanup
        for turn_client in turn_clients:
            await turn_client.close()

if __name__ == '__main__':
    main()