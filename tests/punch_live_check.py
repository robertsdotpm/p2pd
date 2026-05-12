"""
Live-network punch sanity check.

Runs the regular punch plugin against real, externally routable NICs
and a real signaling path (no local TURN, no fixture trickery). Logs
the chosen plugin and the per-pair NAT classification so that the
failure mode -- when one or both pairs sit behind a symmetric NAT --
is observable.

This script is NOT pytest-driven. It is invoked manually:

    python tests/punch_live_check.py

Expected outcomes by NAT mix:

    A=cone, B=cone           punch SHOULD win (PunchPlugin)
    A=cone, B=restrict_port  punch SHOULD win
    A=symmetric, B=*         punch is EXPECTED to fail and TURN wins
    A=*, B=symmetric         punch is EXPECTED to fail and TURN wins

A symmetric-NAT failure here is NOT a bug -- the regular punch
algorithm cannot predict the per-destination port mapping that a
symmetric NAT applies. A separate plugin will eventually cover that
case; until then, TURN is the correct fallback.

Exit code:
    0 -- punch won, OR punch failed and (a or b) is symmetric (expected)
    1 -- punch failed and neither side is symmetric (regression)
"""
import asyncio
import sys

from aionetiface import (
    IP4, Interface, SYMMETRIC_NAT,
    list_interfaces, load_interfaces,
)
from warpgate import Node
from warpgate.node.auto_connect import auto_connect
from warpgate.node.node_defs import NODE_PORT


PORT_A = NODE_PORT + 7000
PORT_B = NODE_PORT + 7001


def nat_label(nat):
    """Pretty NAT-type print."""
    if nat is None:
        return "unknown"
    return "type={0} is_hard={1} can_predict={2}".format(
        nat.get("type"), nat.get("is_hard"), nat.get("can_predict"),
    )


def is_symmetric(addr_map):
    """True if any IP4 if_info on the node is classified SYMMETRIC_NAT."""
    if not addr_map or IP4 not in addr_map:
        return False
    for info in addr_map[IP4].values():
        nat = info.get("nat") or {}
        if nat.get("type") == SYMMETRIC_NAT:
            return True
    return False


async def main():
    if_names = await list_interfaces()
    ifs = await load_interfaces(
        if_names, Interface, min_agree=1, max_agree=4, timeout=4,
    )
    print("[PUNCH-LIVE] loaded {0} ifs: {1}".format(
        len(ifs), [nic.id for nic in ifs],
    ))
    if len(ifs) < 2:
        print("[PUNCH-LIVE] need >=2 NICs; aborting (have {0})".format(len(ifs)))
        return 0

    # Each Node owns one real NIC (probe_ifs[0] -> alice, probe_ifs[1] -> bob),
    # matching the multi-NIC test fixture.
    node_a = Node(ifs=[ifs[0]], ip=None, port=PORT_A)
    node_b = Node(ifs=[ifs[1]], ip=None, port=PORT_B)

    await asyncio.wait_for(node_a.start(), timeout=35)
    await asyncio.wait_for(node_b.start(), timeout=35)

    print("[PUNCH-LIVE] node_a addr_map IP4={0}".format(node_a.addr_map.get(IP4)))
    print("[PUNCH-LIVE] node_b addr_map IP4={0}".format(node_b.addr_map.get(IP4)))
    for if_idx, info in (node_a.addr_map.get(IP4) or {}).items():
        print("[PUNCH-LIVE] node_a if[{0}] nat={1}".format(if_idx, nat_label(info.get("nat"))))
    for if_idx, info in (node_b.addr_map.get(IP4) or {}).items():
        print("[PUNCH-LIVE] node_b if[{0}] nat={1}".format(if_idx, nat_label(info.get("nat"))))

    a_sym = is_symmetric(node_a.addr_map)
    b_sym = is_symmetric(node_b.addr_map)
    print("[PUNCH-LIVE] symmetric flags: a={0} b={1}".format(a_sym, b_sym))

    # Strip direct/reverse so punch is the only non-TURN traversal.
    for name in ("direct_connect", "reverse_connect"):
        node_a.traversal.plugin_loaders.pop(name, None)
    print("[PUNCH-LIVE] node_a plugins(after pop)={0}".format(
        list(node_a.traversal.plugin_loaders.keys())
    ))

    pipe = plugin = None
    try:
        pipe, plugin = await asyncio.wait_for(
            auto_connect(node_a, node_b.addr_bytes, timeout=50),
            timeout=60,
        )
    except asyncio.TimeoutError:
        print("[PUNCH-LIVE] auto_connect timed out")

    plugin_name = type(plugin).__name__ if plugin is not None else None
    print("[PUNCH-LIVE] result: pipe={0!r} plugin={1}".format(pipe, plugin_name))

    rc = 0
    if plugin_name == "PunchPlugin":
        print("[PUNCH-LIVE] PASS punch won")
    elif plugin_name == "TURNPlugin" and (a_sym or b_sym):
        print("[PUNCH-LIVE] EXPECTED: punch failed because one side is symmetric "
              "(a_sym={0} b_sym={1}); TURN took over -- not a bug".format(a_sym, b_sym))
    else:
        print("[PUNCH-LIVE] UNEXPECTED: punch did not win and no side is symmetric "
              "(a_sym={0} b_sym={1}, plugin={2})".format(a_sym, b_sym, plugin_name))
        rc = 1

    if pipe is not None:
        try:
            await asyncio.wait_for(pipe.close(), timeout=5)
        except Exception:
            pass
    try:
        await asyncio.wait_for(node_a.close(), timeout=10)
    except Exception:
        pass
    try:
        await asyncio.wait_for(node_b.close(), timeout=10)
    except Exception:
        pass
    return rc


if __name__ == "__main__":
    rc = asyncio.get_event_loop().run_until_complete(main())
    sys.exit(rc)
