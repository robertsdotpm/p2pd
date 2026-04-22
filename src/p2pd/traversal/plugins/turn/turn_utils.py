"""Helpers for the TURN traversal plugin."""
from aionetiface import *
from ....protocol.turn.turn_client import TURNClient


def rendezvous_rank(key, servers):
    # type: (Any, List[Dict[str, Any]]) -> List[Dict[str, Any]]
    """Rank TURN server dicts by rendezvous hash of key + server identity.

    Both peers independently produce the same ranking from the shared
    plugin_id, so no serv_id needs to be exchanged in the signaling payload.
    Returns a new list of server dicts sorted best-first.
    """
    key_b = to_b(key)

    def score(s):
        # type: (Dict[str, Any]) -> Any
        """Compute a rendezvous hash score for server s against the shared key."""
        return rendezvous_score(key_b, to_b(s["ip"]), str(s["port"]).encode())

    return sorted(servers, key=score, reverse=True)


async def get_turn_client(
    af, server, interface, dest_peer=None, dest_relay=None, msg_cb=None
):
    # type: (Any, Dict[str, Any], Any, Optional[Any], Optional[Any], Optional[Any]) -> Tuple[Any, Any, TURNClient]
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


async def get_first_working_turn_client(af, servers, nic, msg_cb):
    # type: (Any, List[Dict[str, Any]], Any, Any) -> Optional[TURNClient]
    """Try each TURN server in ranked order and return the first one that connects."""
    for server in servers:
        try:
            _, _, turn_client = await get_turn_client(
                af,
                server,
                nic,
                msg_cb=msg_cb,
            )
            return turn_client
        except (OSError, ConnectionError, asyncio.TimeoutError):
            log_exception()
            continue
