import pytest

from p2pd import *


async def turn_msg_cb(msg, client_tup, pipe):
    # print(msg)
    # print(client_tup)
    # print(pipe)
    pipe.got_msg = msg


async def get_turn_client(af, interface, turn_offset):
    # Get a route for this interface.
    route = await interface.route(af).bind()
    ip = TURN_SERVERS[turn_offset][IP4] or TURN_SERVERS[turn_offset][IP6]
    dest = (
        ip,
        TURN_SERVERS[turn_offset]["port"],
    )

    # Implement the TURN protocol for UDP send / recv.
    client = TURNClient(
        turn_addr=dest,
        turn_user=TURN_SERVERS[turn_offset]["user"],
        turn_pw=TURN_SERVERS[turn_offset]["pass"],
        turn_realm=TURN_SERVERS[turn_offset]["realm"],
        route=route,
        # msg_cb=turn_msg_cb
    )

    # Enable blank UDP headers.
    # client.toggle_blank_rudp_headers(True)

    # Wait for authentication and relay address allocation.
    await async_wrap_errors(client.start(), timeout=10)

    # Wait for the client to be ready.
    await client.client_tup_future
    await client.relay_tup_future
    return client


@pytest.mark.network
class TestTurn(unittest.IsolatedAsyncioTestCase):
    async def test_turn_duel_ifs(self):
        # Offset of turn server to use.
        turn_offset = 2

        # Load interface list.
        netifaces = await aionetiface_setup_netifaces()
        try:
            ifs, af = await duel_if_setup(netifaces)
        except Exception:
            return
        assert len(ifs) == 2
        if af is None:
            return

        # Will store the turn clients.
        turn_clients = []
        relay_tup = None
        for interface in ifs:
            client = await get_turn_client(af, interface, turn_offset)
            turn_clients.append(client)

        try:
            # Each turn client white lists the others external IP.
            for if_index in range(0, len(ifs)):
                src_turn = turn_clients[if_index]
                dest_turn = turn_clients[(if_index + 1) % 2]
                peer_tup = await dest_turn.client_tup_future
                relay_tup = await dest_turn.relay_tup_future
                await src_turn.accept_peer(peer_tup, relay_tup)

            # Test message receipt for both clients.
            msg = b"hello, world!"
            for if_index in range(0, len(ifs)):
                interface = ifs[if_index]
                turn_client = turn_clients[(if_index + 1) % 2]

                for i in range(0, 3):
                    await turn_client.send(msg)

                peer_tup = await turn_client.client_tup_future
                sub = tup_to_sub(peer_tup)
                out = await turn_clients[if_index].recv(SUB_ALL)
                assert msg in out
        finally:
            for turn_client in turn_clients:
                await turn_client.close()


if __name__ == "__main__":
    main()
