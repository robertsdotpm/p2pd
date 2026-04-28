"""One-off diagnostic: dump which MQTT brokers a peer subscribes / publishes to.

Used to validate the broker-set non-convergence theory for the
old-OS <-> modern-OS reverse_connect bug: the hypothesis is that
each peer ends up subscribed on its own probe-success subset of
brokers, and the publisher's discovered subset for the destination
pubkey may not intersect the destination's actual subscribe subset
- so the publish lands on a broker the destination never subscribed
to and silently disappears.

Usage:

    # Phase 1: dump self info (pub_hex + protected_clients set).
    python -m p2pd.tools.broker_membership

    # Phase 2: query publish-target sets for one or more peer pubkeys.
    python -m p2pd.tools.broker_membership <peer_pub_hex> [<peer_pub_hex> ...]

In both phases the output is a single JSON object on stdout, easy
to collect via SSH and aggregate offline. Each broker entry gives
(af, host, port) so overlap matrices can be computed across VMs.

Read-only: starts a Node, runs the standard router discovery, then
shuts down. Does not bind a demo listener port.
"""
from typing import Any, Dict, List
import asyncio
import json
import sys

from aionetiface import async_run, IP4
from ..node.node import Node


def fmt_client(client: Any) -> Dict[str, Any]:
    """Render an MQTTClient as a (af, host, port) dict for JSON output."""
    af = getattr(client, "af", None)
    dest = getattr(client, "dest", None) or (None, None)
    host, port = dest if isinstance(dest, (tuple, list)) and len(dest) >= 2 else (None, None)
    return {
        "af": int(af) if af is not None else None,
        "host": host,
        "port": port,
    }


async def main_async(peer_pub_hexes: List[str]) -> int:
    """Start a node, dump self + (optional) per-peer broker membership."""
    print("starting node (this takes a few seconds)...", file=sys.stderr)
    node = await Node().start()

    out = {
        "self_pub_hex": node.kp.public_key_hex,
        "protected": [fmt_client(c) for c in node.router.protected_clients],
        "publish_for": {},
    }

    # Phase 2: for each provided peer pubkey, run get_dest_clients
    # and dump the resulting client set. Local import keeps phase 1
    # cheap (no extra module load) when no peers are given.
    if peer_pub_hexes:
        from sidewire.utils import get_dest_clients
        for tgt in peer_pub_hexes:
            try:
                clients = await get_dest_clients(
                    node.router.nic,
                    tgt,
                    node.router.servers,
                    node.router.clients,
                )
            except Exception as exc:  # noqa: BLE001 -- diagnostic path
                out["publish_for"][tgt] = {"error": "{0}: {1}".format(type(exc).__name__, exc)}
                continue
            out["publish_for"][tgt] = [fmt_client(c) for c in clients]

    print(json.dumps(out, indent=2))

    try:
        await asyncio.wait_for(node.close(), timeout=10)
    except (asyncio.TimeoutError, OSError, ConnectionError):
        pass

    return 0


def main() -> int:
    peer_pub_hexes = sys.argv[1:]
    try:
        return async_run(main_async(peer_pub_hexes))
    except (KeyboardInterrupt, asyncio.CancelledError):
        return 130


if __name__ == "__main__":
    sys.exit(main())
