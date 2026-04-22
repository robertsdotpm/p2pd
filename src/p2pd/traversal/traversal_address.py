"""Address resolution helpers used during NAT traversal."""
from aionetiface import *
from ..node.nickname import *

"""
A nodes PNS address gets resolved to address bytes.
Then because the node may have moved or changed,
an MQTT signaling message asks that node for its most
recent address bytes.
"""


async def get_updated_addr_bytes(node, dest_addr):
    # type: (Any, Any) -> Any
    # type: (Any, Any) -> Any
    """
    Resolve a nickname to address bytes, then ask the peer for its current
    address via the get_addr plugin (MQTT signaling).

    NOTE: This function is superseded by get_updated_addr_from_mqtt which
    uses the plugin system. Kept for reference.
    """
    if not pnp_name_has_tld(dest_addr):
        raise ValueError("dest addr is not a pnp name")

    log_p2p(fstr("Translating '{0}'", (dest_addr,)), node.node_id[:8])

    pkt = await node.nick_client.get(dest_addr)
    if pkt is None or pkt.value is None:
        raise LookupError(fstr("Nickname lookup failed for '{0}'", (dest_addr,)))

    if not pkt.vkc or not isinstance(pkt.vkc, bytes):
        raise ValueError(
            fstr("Missing vkc in nickname response for '{0}'", (dest_addr,))
        )

    addr_bytes = pkt.value
    log_p2p(
        fstr(
            "Resolved '{0}' = '{1}'",
            (
                dest_addr,
                addr_bytes,
            ),
        ),
        node.node_id[:8],
    )

    # Use the plugin system to request the peer's most recent address.
    try:
        updated_bytes = await get_updated_addr_from_mqtt(node, addr_bytes)
        if updated_bytes:
            return updated_bytes
    except (OSError, ConnectionError, asyncio.TimeoutError):
        log_exception()

    return addr_bytes


async def get_updated_addr_from_mqtt(node, dest_bytes):
    # type: (Any, Any) -> Optional[Any]
    # type: (Any, Any) -> Optional[Any]
    af = None  # AF selection is handled inside connect().
    route_type = None
    plugin = await node.connect(af, route_type, dest_bytes, "get_addr")
    try:
        updated_bytes = await asyncio.wait_for(plugin.result, timeout=10)
    except asyncio.TimeoutError:
        log("get_updated_addr_from_mqtt timed out waiting for reply")
        return None
    return updated_bytes
