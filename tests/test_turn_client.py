import asyncio
import unittest

from aionetiface.testing import AsyncTestCase
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


class TestTurn(AsyncTestCase):
    async def test_turn_duel_ifs(self):
        # Load interface list.
        netifaces = await aionetiface_setup_netifaces()
        try:
            ifs, af = await duel_if_setup(netifaces)
        except Exception:
            return
        assert len(ifs) == 2
        if af is None:
            return

        # Walk every configured TURN server until one succeeds for both
        # clients. A fixed turn_offset (2) used to fail the test entirely
        # whenever that single server was rate-limiting / down / blocked
        # by the matrix VM's outbound rules; looping turns a single-server
        # outage into a transient skip.
        last_exc = None
        for turn_offset in range(len(TURN_SERVERS)):
            turn_clients = []
            try:
                for interface in ifs:
                    client = await get_turn_client(af, interface, turn_offset)
                    turn_clients.append(client)
            except (OSError, ConnectionError, asyncio.TimeoutError, AssertionError) as exc:
                last_exc = exc
                # Cleanup whatever did succeed before moving on.
                for c in turn_clients:
                    try:
                        await c.close()
                    except Exception:
                        pass
                print("[TURN-DUEL] server offset {0} failed allocation: {1!r}; "
                      "trying next".format(turn_offset, exc))
                continue

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
                # Success: stop looping over remaining servers.
                return
            finally:
                for turn_client in turn_clients:
                    try:
                        await turn_client.close()
                    except Exception:
                        pass
        # All configured TURN servers were unreachable -- ENV.
        self.skipTest(
            "TURN duel-if test could not allocate against any of the "
            "{0} configured TURN servers (last error: {1!r})".format(
                len(TURN_SERVERS), last_exc,
            )
        )


if __name__ == "__main__":
    main()
