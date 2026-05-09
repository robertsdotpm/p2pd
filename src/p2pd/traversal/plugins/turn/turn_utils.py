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


async def get_first_working_turn_client(
    af,
    servers,
    nic,
    msg_cb,
    per_server_timeout=PER_SERVER_TIMEOUT,
):
    """Try each TURN server in ranked order and return the first one that connects.

    Each server attempt is bounded by ``per_server_timeout`` so a single
    unreachable / slow server (typically one with high failed_tests in
    servers.json that rendezvous_rank still happened to hash up front)
    cannot eat the plugin's overall budget. The plugin's PLUGIN_CONF
    timeout must be set high enough to absorb several of these
    per-server caps in a row -- if it isn't, we'll bail before
    finding a working relay even though the network is fine.
    """
    for server in servers:
        try:
            _, _, turn_client = await asyncio.wait_for(
                get_turn_client(
                    af,
                    server,
                    nic,
                    msg_cb=msg_cb,
                ),
                timeout=per_server_timeout,
            )
            return turn_client
        except (OSError, ConnectionError, asyncio.TimeoutError):
            log_exception()
            continue
