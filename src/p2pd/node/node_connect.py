"""Outbound connection logic for a p2pd node."""
import asyncio
import time
from aionetiface import (
    sort_ips_by_nic, route_pool_from_ips, fstr, log, parse_node_addr,
    IP4, IP6, NIC_BIND, EXT_BIND, LOOPBACK_BIND,
)
from .node_utils import enrich_addr_map_with_loopback
from ..traversal.traversal_address import get_updated_addr_from_mqtt, pnp_name_has_tld


def apply_listen_ips(node):
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


async def resolve_pnp_addr(node, pnp_addr):
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
    pkt_age = time.time() - getattr(pkt, "pnp_ts", time.time())
    if pkt_age > 300:
        log(fstr(
            "PNP record for '{0}' is {1}s old; attempting MQTT refresh",
            (pnp_addr, int(pkt_age)),
        ))
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
        if pkt_age > 300:
            log(fstr(
                "Warning: MQTT refresh failed; using {0}s-old PNP record for '{1}'",
                (int(pkt_age), pnp_addr),
            ))

    return addr_bytes, dest_vk, source


def iter_viable_pairs(
    af,
    route_type,
    src_map,
    dest_map,
):
    """Yield every (src, dest) pair that's distinct enough
    to be useful for *route_type*, in priority order.

    NIC_BIND      different NIC IPs
    LOOPBACK_BIND both sides advertise a loopback alias
    EXT_BIND      different external IPs
    Other / None  every pair in priority order, no filter
    """
    # Local import keeps node_connect free of a hard import on the
    # traversal package at module load time.
    from ..traversal.traversal_utils import get_if_infos_order

    for src, dest in get_if_infos_order(af, route_type, src_map, dest_map):
        if route_type == NIC_BIND:
            if int(src["nic"]) == int(dest["nic"]):
                continue
        elif route_type == LOOPBACK_BIND:
            if src.get("loopback") is None or dest.get("loopback") is None:
                continue
        elif route_type == EXT_BIND:
            if int(src["ext"]) == int(dest["ext"]):
                continue
        yield src, dest


def select_first_viable_pair(
    af,
    route_type,
    src_map,
    dest_map,
):
    """First-only convenience wrapper around iter_viable_pairs."""
    for pair in iter_viable_pairs(af, route_type, src_map, dest_map):
        return pair
    return None


async def connect(node, af, route_type, pnp_addr, plugin_name=None):
    """Resolve the destination address and run the traversal plugin to establish a P2P connection.

    reverse_connect is special-cased: per the any-pathway design the
    initiator does not pin a (src, dest) interface pair -- the
    responder is free to pick whichever combo works at its end. The
    initiator only optionally constrains (af, route_type). When either
    of those is None the constraint is left as the any-pathway sentinel
    so the responder iterates compatible options.
    """
    addr_bytes, dest_vk, _ = await resolve_pnp_addr(node, pnp_addr)
    dest_map = parse_node_addr(addr_bytes)
    enrich_addr_map_with_loopback(dest_map)
    # Pass dest's advertised broker hints so SmartPipe prefers them
    # over rendezvous discovery -- the dest GUARANTEED subscribed
    # at those brokers when it published the addr, sidestepping
    # cross-peer broker-set non-convergence.
    sig_pipe = await node.router.pipe(
        dest_map["pub_key_hex"],
        use_cache=True,
        hint_brokers=dest_map.get("mqtt_brokers") or [],
    )

    src_map = node.addr_map
    if dest_vk:
        dest_map["vk"] = dest_vk

    # Plugins routed through the fan_out meta-plugin: the initiator
    # only optionally constrains (af, route_type); pair selection is
    # done per-combo by fan_out, racing every viable pair concurrently
    # and returning the first non-None pipe. reverse_connect needs
    # this because by design the initiator never pins the pair (the
    # responder is free to pick); direct_connect benefits because
    # racing pairs catches multi-NIC mesh/mobile setups where the
    # first iter_viable_pairs entry may be reachable from us but not
    # from them.
    FAN_OUT_PLUGINS = ("reverse_connect", "direct_connect")
    if plugin_name in FAN_OUT_PLUGINS:
        same_machine = (
            src_map.get("machine_id") == dest_map.get("machine_id")
        )
        plugin = node.traversal.create_plugin(
            af=None,
            route_type=None,
            src=None,
            dest=None,
            same_machine=same_machine,
            plugin_name="fan_out",
        )
        plugin.set_addrs(src_map, dest_map)
        plugin.sig_pipe = sig_pipe
        plugin.configure_target(plugin_name, af=af, route_type=route_type)
        await node.traversal.run_plugin(plugin)
        return plugin

    if not af:
        for try_af in (IP4, IP6):
            if len(src_map[try_af]) and len(dest_map[try_af]):
                af = try_af
                break

    if not af:
        raise ValueError("No supported shared AF.")

    # Diagnostic only: warn when a (src, dest) pair share their NIC/EXT
    # IP for the same if_index -- that pair won't be usable. Used to
    # be a hard `raise ValueError` here, but that bailed the whole
    # connect even when OTHER pairs were viable. Two nodes with two
    # NICs each can have ONE pair share an IP (e.g. both on the same
    # LAN router so both report the same external WAN IP) while a
    # *different* pairing of NICs is reachable. iter_viable_pairs
    # below already filters out the bad pair on its own (lines 75-85
    # of this file), so we just log here and let the per-pair walk
    # try the alternatives.
    if plugin_name == "get_addr":
        pass
    elif route_type == NIC_BIND:
        for if_idx, dest in dest_map[af].items():
            src = src_map[af].get(if_idx)
            if src is None:
                continue
            if int(dest["nic"]) == int(src["nic"]):
                log(fstr(
                    "node.connect: dest if_index {0} shares NIC IP {1} "
                    "with this node for AF {2} -- this pair will be "
                    "skipped; trying other pairs.",
                    (if_idx, dest["nic"].ip, af),
                ))
    elif route_type in (EXT_BIND, None):
        for if_idx, dest in dest_map[af].items():
            src = src_map[af].get(if_idx)
            if src is None:
                continue
            if int(dest["ext"]) == int(src["ext"]):
                log(fstr(
                    "node.connect: dest if_index {0} shares external IP "
                    "{1} with this node for AF {2} -- this pair will be "
                    "skipped; trying other pairs.",
                    (if_idx, dest["ext"].ip, af),
                ))

    # Walk every viable (src, dest) pair in priority order.
    # If the plugin raises ValueError on a pair (e.g. random_probe on
    # a non-(sym, non-sym) pair, or a same-IP self-target check),
    # log the reason and try the next pair.  Only when *every* pair
    # fails do we surface the last ValueError to the caller.
    last_err = None
    tried = 0
    for src, dest in iter_viable_pairs(af, route_type, src_map, dest_map):
        tried += 1
        try:
            return await node.traversal.attempt_plugin(
                src_map=src_map,
                dest_map=dest_map,
                sig_pipe=sig_pipe,
                plugin_name=plugin_name,
                src=src,
                dest=dest,
                af=af,
                route_type=route_type,
            )
        except ValueError as exc:
            log(
                "node.connect: pair (src_if={0}, dest_if={1}) rejected "
                "by {2}: {3}; trying next pair".format(
                    src.get("if_index"), dest.get("if_index"),
                    plugin_name, exc,
                )
            )
            last_err = exc
            continue

    if tried == 0:
        raise ValueError(
            "No viable (src, dest) interface pair for af={} route_type={}".format(
                af, route_type,
            )
        )
    # tried > 0 but every attempt raised ValueError -- re-surface the
    # last reason so the caller (and the demo) sees something useful.
    raise last_err
