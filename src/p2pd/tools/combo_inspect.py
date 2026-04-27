"""Inspect every (plugin, af, route_type, src, dest) combo for a node pair.

Usage:
    python -m p2pd.tools.combo_inspect <addr_b>
    python -m p2pd.tools.combo_inspect <addr_a> <addr_b>

Single-arg form: the local host is treated as side A. addr_b is a remote
PNP nickname or raw address.

Two-arg form: both addresses are resolved via the local host's signal
channel; neither is treated as self. Useful for inspecting what
auto_connect would do for a hypothetical pair you're not actually one
side of.

Each combo is printed as a row with the plugin name, address family,
route type, and the relevant src / dest info fields. Address resolution
goes through the same code path as Node.connect (resolve_pnp_addr +
parse_node_addr + enrich_addr_map_with_loopback) so the output reflects
what auto_connect would actually see at runtime.

Read-only: no plugin runs, no TCP/UDP connect attempted. Just enumerates.
"""

from typing import Any, List, Optional
import argparse
import asyncio
import sys

from aionetiface import (
    IP4, IP6, NIC_BIND, EXT_BIND, LOOPBACK_BIND,
    async_run, parse_node_addr, to_s,
)
from ..node.node import Node
from ..node.node_connect import resolve_pnp_addr
from ..node.node_utils import enrich_addr_map_with_loopback
from ..node.auto_connect import auto_combos


ROUTE_NAMES = {
    NIC_BIND:      "NIC_BIND",
    EXT_BIND:      "EXT_BIND",
    LOOPBACK_BIND: "LOOPBACK_BIND",
}

AF_NAMES = {
    IP4: "IP4",
    IP6: "IP6",
}


def fmt_info(info: Any) -> str:
    """Render a src_info / dest_info dict as a compact one-line string."""
    if info is None:
        return "-"
    parts = []
    for k in ("if_index", "nic", "ext", "loopback", "port"):
        if k in info and info.get(k) is not None:
            parts.append("{0}={1}".format(k, info[k]))
    nat = info.get("nat") or {}
    if nat:
        nt = nat.get("type")
        if nt is not None:
            parts.append("nat={0}".format(nt))
    return " ".join(parts)


async def resolve_remote(node: Any, addr: str) -> Any:
    """Resolve a PNP nickname (or raw addr_bytes hex) through the local node's
    signal channel and return the parsed addr_map ready for combo enumeration.
    """
    addr_bytes, _vk, _ = await resolve_pnp_addr(node, addr)
    addr_map = parse_node_addr(addr_bytes)
    enrich_addr_map_with_loopback(addr_map)
    return addr_bytes, addr_map


def render_combos(
    label_a: str,
    label_b: str,
    node: Any,
    src_map: Any,
    dest_map: Any,
) -> None:
    """Print a header + one row per combo from auto_combos."""
    combos = auto_combos(node, src_map, dest_map)

    print()
    print("=" * 78)
    print("  combos: {0}  ({1} -> {2})".format(len(combos), label_a, label_b))
    print("=" * 78)

    if not combos:
        print()
        print("  no viable combos -- pair has no compatible (af, route_type) arc.")
        print()
        return

    # Group by (af, route_type) for readability.
    bucket = {}
    order = []
    for plugin_name, af, route_type, src_info, dest_info in combos:
        key = (af, route_type)
        if key not in bucket:
            bucket[key] = []
            order.append(key)
        bucket[key].append((plugin_name, src_info, dest_info))

    for af, route_type in order:
        rows = bucket[(af, route_type)]
        print()
        print("  --- {0} / {1} ({2} combo{3}) ---".format(
            AF_NAMES.get(af, str(af)),
            ROUTE_NAMES.get(route_type, str(route_type)),
            len(rows),
            "" if len(rows) == 1 else "s",
        ))
        for plugin_name, src_info, dest_info in rows:
            print("    {0:<18} src[{1}]   dest[{2}]".format(
                plugin_name, fmt_info(src_info), fmt_info(dest_info),
            ))
    print()


async def main_async(args: argparse.Namespace) -> int:
    """Start a local node, resolve target addresses, render combos, exit."""
    addrs = args.addrs
    if len(addrs) not in (1, 2):
        print("error: pass 1 or 2 addresses", file=sys.stderr)
        return 2

    print("starting local node (this is needed for address resolution)...")
    node = await Node().start()

    try:
        if len(addrs) == 1:
            # Local-as-A flow: src is local, resolve B remotely.
            self_map = node.addr_map.copy() if hasattr(node.addr_map, "copy") else dict(node.addr_map)
            self_map["machine_id"] = node.machine_id
            self_map["pub_key_hex"] = to_s(node.kp.compact_public_key.hex()) if hasattr(node.kp.compact_public_key, "hex") else None
            enrich_addr_map_with_loopback(self_map)

            _, dest_map = await resolve_remote(node, addrs[0])
            render_combos("local", addrs[0], node, self_map, dest_map)
        else:
            _, src_map = await resolve_remote(node, addrs[0])
            _, dest_map = await resolve_remote(node, addrs[1])
            render_combos(addrs[0], addrs[1], node, src_map, dest_map)
    finally:
        try:
            await asyncio.wait_for(node.close(), timeout=10)
        except (asyncio.TimeoutError, OSError, ConnectionError):
            pass

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Print the (plugin, af, route_type, src, dest) combos "
                    "auto_connect would race for a node pair, without actually "
                    "connecting.",
    )
    parser.add_argument(
        "addrs",
        nargs="+",
        help="One or two PNP nicknames (e.g. abc123.p2p) or raw "
             "addr_bytes hex strings. Single arg = local host is side A.",
    )
    args = parser.parse_args()
    try:
        return async_run(main_async(args))
    except (KeyboardInterrupt, asyncio.CancelledError):
        return 130


if __name__ == "__main__":
    sys.exit(main())
