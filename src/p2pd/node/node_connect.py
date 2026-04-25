"""Outbound connection logic for a p2pd node."""
from typing import Any, Optional, Tuple
import asyncio
from aionetiface import (
    sort_ips_by_nic, route_pool_from_ips, fstr, log, parse_node_addr,
    IP4, IP6, NIC_BIND, EXT_BIND,
)
from ..traversal.traversal_address import get_updated_addr_from_mqtt, pnp_name_has_tld


def apply_listen_ips(node: Any) -> None:
    """Restrict node.ifs to NICs that own a listen IP, and narrow each NIC's route pool."""
    by_nic = sort_ips_by_nic(node.listen_ips, node.ifs)
    found = set()
    new_ifs = []
    for nic in node.ifs:
        if by_nic[nic.id]:
            found.update(by_nic[nic.id])
            nic.rp = route_pool_from_ips(by_nic[nic.id], nic)
            new_ifs.append(nic)
    node.ifs = new_ifs

    missing = [ip for ip in node.listen_ips if ip not in found]
    if missing:
        raise ValueError("listen IPs not found on any interface: " + ", ".join(missing))


async def resolve_pnp_addr(node: Any, pnp_addr: Any) -> Tuple[Any, Optional[Any], Optional[str]]:
    """Resolve a PNP nickname to (addr_bytes, dest_vk, source).

    source is "mqtt" if the address was refreshed via the MQTT router,
    or "nickname" if only the namebump record was available.
    Returns (pnp_addr, None, None) unchanged if pnp_addr is not a TLD name."""
    if not pnp_name_has_tld(pnp_addr):
        return pnp_addr, None, None

    pkt = await node.nick_client.get(pnp_addr)
    if pkt is None or pkt.value is None:
        raise LookupError(fstr("Nickname '{0}' not found", (pnp_addr,)))
    addr_bytes = pkt.value
    dest_vk = pkt.vkc
    source = "nickname"
    try:
        updated_addr_bytes = await asyncio.wait_for(
            get_updated_addr_from_mqtt(node, addr_bytes), timeout=10
        )
        if updated_addr_bytes:
            addr_bytes = updated_addr_bytes
            source = "mqtt"
    except asyncio.TimeoutError:
        log("Timeout MQTT get updated bytes " + str(pnp_addr))

    return addr_bytes, dest_vk, source


def select_first_viable_pair(
    af: Any,
    route_type: Any,
    src_map: Any,
    dest_map: Any,
) -> Optional[Tuple[Any, Any]]:
    """Walk get_if_infos_order in priority order and return the first
    (src_info, dest_info) pair whose addresses are distinct enough to be
    useful for the given route_type.

    NIC_BIND wants different NIC IPs (matching local IPs would collide on
    the same machine). EXT_BIND wants different external IPs (matching ext
    IPs would loop back through the WAN to the local stack). For other
    route_types or `None`, the first pair in priority order is returned
    without further filtering.
    """
    # Local import keeps node_connect free of a hard import on the
    # traversal package at module load time.
    from ..traversal.traversal_utils import get_if_infos_order

    for src_info, dest_info in get_if_infos_order(af, route_type, src_map, dest_map):
        if route_type == NIC_BIND:
            if int(src_info["nic"]) == int(dest_info["nic"]):
                continue
        elif route_type == EXT_BIND:
            if int(src_info["ext"]) == int(dest_info["ext"]):
                continue
        return src_info, dest_info
    return None


async def connect(node: Any, af: Any, route_type: Any, pnp_addr: Any, plugin_name: Optional[str] = None) -> Any:
    """Resolve the destination address and run the traversal plugin to establish a P2P connection."""
    addr_bytes, dest_vk, _ = await resolve_pnp_addr(node, pnp_addr)
    dest_map = parse_node_addr(addr_bytes)
    sig_pipe = await node.router.pipe(dest_map["pub_key_hex"], use_cache=True)

    src_map = node.addr_map
    if dest_vk:
        dest_map["vk"] = dest_vk

    if not af:
        for try_af in (IP4, IP6):
            if len(src_map[try_af]) and len(dest_map[try_af]):
                af = try_af
                break

    if not af:
        raise ValueError("No supported shared AF.")

    # Sanity check: running multiple node instances with the same IP on
    # the same interface is not supported. The check is keyed on if_index
    # so that two nodes can legitimately share an IP on *different*
    # interfaces (e.g. both have fe80::2 but on separate NICs).
    if plugin_name == "get_addr":
        pass
    elif route_type == NIC_BIND:
        for if_idx, dest_info in dest_map[af].items():
            src_info = src_map[af].get(if_idx)
            if src_info is None:
                continue
            if int(dest_info["nic"]) == int(src_info["nic"]):
                raise ValueError(
                    "Local route selected but dest if_index {} shares "
                    "NIC IP {} with this node for AF {} — "
                    "punch will fail.".format(if_idx, dest_info["nic"].ip, af)
                )
    elif route_type in (EXT_BIND, None):
        for if_idx, dest_info in dest_map[af].items():
            src_info = src_map[af].get(if_idx)
            if src_info is None:
                continue
            if int(dest_info["ext"]) == int(src_info["ext"]):
                raise ValueError(
                    "External route selected but dest if_index {} shares "
                    "external IP {} with this node for AF {} — "
                    "cannot connect to yourself via WAN addresses.".format(
                        if_idx, dest_info["ext"].ip, af
                    )
                )

    # attempt_plugin is now single-pair: pick the highest-priority viable
    # (src_info, dest_info) pair from get_if_infos_order. Manual control
    # via explicit if_index args can be added later if needed.
    pair = select_first_viable_pair(af, route_type, src_map, dest_map)
    if pair is None:
        raise ValueError(
            "No viable (src, dest) interface pair for af={} route_type={}".format(
                af, route_type,
            )
        )
    src_info, dest_info = pair

    return await node.traversal.attempt_plugin(
        src_map=src_map,
        dest_map=dest_map,
        sig_pipe=sig_pipe,
        plugin_name=plugin_name,
        src_info=src_info,
        dest_info=dest_info,
        af=af,
        route_type=route_type,
    )
