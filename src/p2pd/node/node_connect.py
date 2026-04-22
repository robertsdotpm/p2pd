import asyncio
from aionetiface import *
from .node_utils import *
from ..traversal.traversal_address import *
from ..traversal.plugins.direct_connect.main import DirectConnect
from ..traversal.plugins.get_addr.main import GetAddrPlugin
from ..traversal.plugins.return_addr.main import ReturnAddrPlugin
from ..traversal.plugins.reverse_connect.main import ReverseConnectPlugin


def apply_listen_ips(node):
    # type: (Any) -> None
    """Restrict each NIC's route pool to the explicitly requested listen IPs."""
    by_nic = sort_ips_by_nic(node.listen_ips, node.ifs)
    found = set()
    for nic in node.ifs:
        if by_nic[nic.id]:
            found.update(by_nic[nic.id])
            nic.rp = route_pool_from_ips(by_nic[nic.id], nic)

    missing = [ip for ip in node.listen_ips if ip not in found]
    if missing:
        raise ValueError("listen IPs not found on any interface: " + ", ".join(missing))


def install_default_plugins(node):
    # type: (Any) -> None
    node.traversal.install_plugin("direct_connect", {"class": DirectConnect})
    node.traversal.install_plugin("get_addr", {"class": GetAddrPlugin})
    node.traversal.install_plugin("return_addr", {"class": ReturnAddrPlugin})
    node.traversal.install_plugin("reverse_connect", {"class": ReverseConnectPlugin})
    node.traversal.install_plugin_done_callback(node.on_plugin_done)


async def resolve_pnp_addr(node, pnp_addr):
    # type: (Any, Any) -> Tuple[Any, Optional[Any], Optional[str]]
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


async def connect(node, af, route_type, pnp_addr, plugin_name=None):
    # type: (Any, Any, Any, Any, Optional[str]) -> Any
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
    # the same interface is not supported.  The check is keyed on if_index
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
                    "Local route selected but dest if_index %d shares "
                    "NIC IP %s with this node for AF %s — "
                    "punch will fail." % (if_idx, dest_info["nic"].ip, af)
                )
    elif route_type in (EXT_BIND, None):
        for if_idx, dest_info in dest_map[af].items():
            src_info = src_map[af].get(if_idx)
            if src_info is None:
                continue
            if int(dest_info["ext"]) == int(src_info["ext"]):
                raise ValueError(
                    "External route selected but dest if_index %d shares "
                    "external IP %s with this node for AF %s — "
                    "cannot connect to yourself via WAN addresses."
                    % (if_idx, dest_info["ext"].ip, af)
                )

    return await node.traversal.attempt_plugin(
        src_map=src_map,
        dest_map=dest_map,
        sig_pipe=sig_pipe,
        plugin_name=plugin_name,
        af=af,
        route_type=route_type,
    )
