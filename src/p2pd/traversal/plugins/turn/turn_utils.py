"""Helpers for the TURN traversal plugin."""
import asyncio
from aionetiface import to_b, rendezvous_score, log_exception
from .turn_client import TURNClient


def rendezvous_rank(key, servers):
    """Rank TURN server dicts by rendezvous hash of key + server identity.

    Both peers independently produce the same ranking from the shared
    plugin_id, so no serv_id needs to be exchanged in the signaling payload.
    Returns a new list of server dicts sorted best-first.
    """
    key_b = to_b(key)

    def score(s):
        """Compute a rendezvous hash score for server s against the shared key."""
        return rendezvous_score(key_b, to_b(s["ip"]), str(s["port"]).encode())

    return sorted(servers, key=score, reverse=True)


async def get_turn_client(
af,
    server,
    interface,
    dest_peer=None,
    dest_relay=None,
    msg_cb=None,
):
    """Connect to a TURN server, allocate a relay, and optionally whitelist a peer."""
    turn_client = TURNClient(
        af=af,
        dest=(server["ip"], server["port"]),
        nic=interface,
        auth=(server["user"], server["password"]),
        realm=None,
        msg_cb=msg_cb,
    )

    await asyncio.wait_for(turn_client.start(), 10)

    peer_tup = await turn_client.client_tup_future
    relay_tup = await turn_client.relay_tup_future

    if None not in [dest_peer, dest_relay]:
        await asyncio.wait_for(turn_client.accept_peer(dest_peer, dest_relay), 6)

    return peer_tup, relay_tup, turn_client


PER_SERVER_TIMEOUT = 6.0


RACE_BATCH_SIZE = 2


async def get_first_working_turn_client(
    af,
    servers,
    nic,
    msg_cb,
    per_server_timeout=PER_SERVER_TIMEOUT,
    race_n=RACE_BATCH_SIZE,
):
    """Race the top race_n TURN servers concurrently; first to allocate wins.

    The previous shape was a strictly-sequential walk, so a single slow
    server at the head of the rendezvous-rank ate per_server_timeout
    (6 s default) before the next was tried. Public TURN endpoints
    have observable per-attempt failure rates in the matrix data
    (cycle 3 win11 just showed turn=- with no obvious initiator-side
    fault); racing 2 candidates in parallel turns the wallclock
    behaviour from "sum of failures" into "min of failures" without
    changing what success looks like to the responder.

    Coordination with the responder is preserved: the winner's dest
    tuple is what gets sent in the initiator's TURNMsg.payload, so
    the responder still allocates on the SAME server we landed on.
    Cancelled in-flight allocations leave a relay reservation on the
    losing server that expires under its lease (~10 min default);
    no leak.

    On total batch failure (all race_n candidates timed out / errored),
    fall through to the original sequential walk over the rest. This
    preserves the renegotiation MAX_RENEGOTIATIONS budget upstream.
    """
    if not servers:
        return None

    async def try_one(server):
        try:
            _, _, turn_client = await asyncio.wait_for(
                get_turn_client(af, server, nic, msg_cb=msg_cb),
                timeout=per_server_timeout,
            )
            return turn_client
        except (OSError, ConnectionError, asyncio.TimeoutError):
            log_exception()
            return None

    batch = list(servers[:race_n])
    rest = list(servers[race_n:])

    if len(batch) > 1:
        tasks = [asyncio.ensure_future(try_one(s)) for s in batch]
        winner = None
        try:
            for fut in asyncio.as_completed(tasks):
                client = None
                try:
                    client = await fut
                except (OSError, ConnectionError, asyncio.TimeoutError):
                    client = None
                if client is not None:
                    winner = client
                    break
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        if winner is not None:
            return winner
    elif batch:
        client = await try_one(batch[0])
        if client is not None:
            return client

    # Batch failed -- sequential fallthrough over remaining servers.
    for server in rest:
        client = await try_one(server)
        if client is not None:
            return client
    return None
