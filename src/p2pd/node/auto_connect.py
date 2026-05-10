"""auto_connect: phase-based connection establishment.

Four phases run in order. The first phase to produce a viable pipe
wins; auto_connect short-circuits and returns it.

  Phase 1 -- direct_connect / reverse_connect
            Race every (plugin x af x route_type x src x dest) combo
            concurrently. 3-second total budget. LOOPBACK_BIND combos
            are eligible when both sides advertise a loopback alias
            (same-machine peers).

  Phase 2 -- tcp_punch
            NIC_BIND sub-phase first; if no NIC_BIND combos exist or
            none win, EXT_BIND. Within each sub-phase, IPv4 first then
            IPv6 (never concurrent). NICs on each side are sorted by
            info["nat"]["type"] ascending so easiest NATs pair first.
            Each parallel slot is a matching: no two attempts in a
            slot share a src NIC or a dest NIC. Slots advance only
            once every parallel attempt has finished or timed out.

  Phase 3 -- udp_punch + random_probe
            Identical scheduling to Phase 2. Both plugins race
            concurrently within each scheduled (src, dest) pair.

  Phase 4 -- turn
            Sequential, no concurrency. Up to TURN_TOTAL_CAP attempts
            in total. Prefer a fresh dest NIC each attempt; reuse one
            only when the dest side has no untried NIC left.

The `plugins=` argument filters which phases run. A phase is skipped
when none of its plugins are in the configured set.
"""
import asyncio
from aionetiface import (
    IP4, IP6, IPRange, NIC_BIND, EXT_BIND, LOOPBACK_BIND, TCP, UDP,
    af_bitlen, fstr, log, log_exception, parse_node_addr,
)
from aionetiface.nic.nat.nat_defs import SYMMETRIC_NAT
from .node_connect import resolve_pnp_addr
from .node_utils import enrich_addr_map_with_loopback
from ..traversal.traversal_utils import close_plugin
from ..traversal.strategy_registry import plugin_registry


def plugins_for_phase(phase):
    """Return plugin names registered for a cascade phase, in registration order."""
    return tuple(c.name for c in plugin_registry if getattr(c, "phase", None) == phase)


def plugins_for_protocol(protocol):
    """Return the default plugin set for a transport.

    `protocol=TCP` -- only stream plugins.  The returned pipe has TCP semantics.
    `protocol=UDP` -- only datagram plugins.  The returned pipe has UDP semantics.
    `protocol=None` -- every cascade plugin, mixed transport.  Caller must be
                       ready to handle either pipe shape.

    Plugin classes set `transport = TCP` / `UDP` (the SOCK_STREAM /
    SOCK_DGRAM constants from aionetiface).  Compare directly against
    those enums.
    """
    if protocol not in (TCP, UDP, None):
        raise ValueError("protocol must be TCP, UDP, or None")

    out = []
    for c in plugin_registry:
        if getattr(c, "phase", None) is None:
            continue  # non-cascade helper
        if protocol is None or getattr(c, "transport", None) == protocol:
            out.append(c.name)
    return tuple(out)

PHASE1_BUDGET = 3.0
TURN_TOTAL_CAP = 3
DEFAULT_PLUGIN_TIMEOUT = 25.0


# ---------------------------------------------------------------------------
# Pair filtering primitives
# ---------------------------------------------------------------------------

def af_compatible(src_map, dest_map, af):
    """True if both nodes have at least one interface for this address family."""
    return bool(src_map.get(af)) and bool(dest_map.get(af))


def pair_distinct(route_type, src, dest):
    """Per-pair validity for a route type.

    NIC_BIND      different NIC IPs (otherwise bind/connect collide)
    LOOPBACK_BIND both sides advertise a loopback alias (different by
                  construction since alias is per-pubkey)
    EXT_BIND      different external IPs (otherwise connect loops
                  through the router back to the local stack)
    """
    if route_type == NIC_BIND:
        return int(src["nic"]) != int(dest["nic"])
    if route_type == LOOPBACK_BIND:
        return (
            src.get("loopback") is not None
            and dest.get("loopback") is not None
        )
    if route_type == EXT_BIND:
        return int(src["ext"]) != int(dest["ext"])
    return True


def same_lan(af, src, dest):
    """True when src and dest can reach each other on the LAN.

    Mirrors traversal_utils.select_dest_ipr's same-LAN detection so
    NIC_BIND combos are only generated for peers actually on the same
    L2 segment / same NAT. Cross-internet peers have private NIC IPs
    that aren't routable from each other -- generating NIC_BIND combos
    for them just burns the slot budget firing SYNs into RFC1918 space.

    Detection prefers the wire-encoded NIC subnet when the peer's addr
    advertises one; otherwise falls back to the v4 ext-equality
    heuristic (same NAT -> shared external IP).
    """
    src_nic_subnet = getattr(src.get("nic"), "subnet", None)
    if src_nic_subnet is not None and src_nic_subnet > 0:
        host_bits = af_bitlen(af) - src_nic_subnet
        try:
            if af == IP6 and str(src["nic"]).lower().startswith("fe80:"):
                src_net = IPRange(str(src["ext"]), bitlen=host_bits)
                return dest.get("ext") is not None and dest["ext"] in src_net
            src_net = IPRange(str(src["nic"]), bitlen=host_bits)
            in_nic = dest.get("nic") is not None and dest["nic"] in src_net
            in_ext = dest.get("ext") is not None and dest["ext"] in src_net
            return in_nic or in_ext
        except (ValueError, TypeError):
            return False
    src_ext = src.get("ext")
    dest_ext = dest.get("ext")
    return src_ext is not None and dest_ext is not None and src_ext == dest_ext


def is_same_machine(src_map, dest_map):
    """True if both addr_maps belong to the same physical host."""
    sid = src_map.get("machine_id")
    did = dest_map.get("machine_id")
    return bool(sid) and sid == did


def viable_pairs_for_arc(
    af,
    route_type,
    src_map,
    dest_map,
):
    """Ordered (src, dest) pairs that survive per-pair filtering.

    Different-machine peers: restricted to matching-if_index pairs (alice's
    NIC0 may not have a route to bob's NIC1's subnet across NATs).

    Same-machine peers: emit the cross-product. Both nodes' NICs share one
    kernel routing table so dest["nic"] is reachable from any src NIC
    via the local stack. Matching-if_index pairs come first so direct
    in-subnet paths are tried before cross-subnet local routing.
    """
    src_af = src_map.get(af, {}) or {}
    dest_af = dest_map.get(af, {}) or {}
    if not src_af or not dest_af:
        return []

    same_machine = is_same_machine(src_map, dest_map)

    def viable(src, dest):
        if not pair_distinct(route_type, src, dest):
            return False
        # NIC_BIND combos for cross-internet peers fire SYNs at peer's
        # private RFC1918 LAN IP, which isn't routable. Gate on same_lan
        # (or same_machine, which is implicitly same_lan) so the slot
        # budget isn't burned on combos that can't possibly converge.
        # LOOPBACK_BIND has its own same_machine semantics handled by
        # pair_distinct's loopback check; EXT_BIND is global by nature.
        if route_type == NIC_BIND and not (same_machine or same_lan(af, src, dest)):
            return False
        return True

    pairs = []
    seen = set()

    for if_idx, dest in dest_af.items():
        src = src_af.get(if_idx)
        if src is None:
            continue
        if viable(src, dest):
            seen.add((id(src), id(dest)))
            pairs.append((src, dest))

    if same_machine:
        for src in src_af.values():
            for dest in dest_af.values():
                key = (id(src), id(dest))
                if key in seen:
                    continue
                if viable(src, dest):
                    pairs.append((src, dest))

    return pairs


def plugin_supports_route_type(loader, route_type):
    """True if the plugin loader's class accepts this route_type.

    Reads ``route_types`` off the loader's plugin class
    (default: every route_type allowed).
    """
    if loader is None:
        return True
    cls = loader.get("class") if isinstance(loader, dict) else None
    if cls is None:
        return True
    supported = getattr(cls, "route_types", None)
    if supported is None:
        return True
    return route_type in supported


def plugin_timeout(loader):
    """Per-plugin declared timeout from its loader meta, with a fallback."""
    if isinstance(loader, dict):
        t = loader.get("timeout")
        if t is not None:
            return float(t)
    return DEFAULT_PLUGIN_TIMEOUT


# ---------------------------------------------------------------------------
# Attempt + race helpers
# ---------------------------------------------------------------------------

async def attempt_one_combo(
    node,
    sig_pipe,
    src_map,
    dest_map,
    combo,
):
    """Run one (plugin, af, route_type, src, dest) attempt to completion.

    For plugins whose run() returns early and resolves plugin.result
    from a background task (tcp_punch, udp_punch, random_probe via
    delayed_start_punching_proc), we need to await plugin.result
    before returning -- otherwise race_combos sees an unresolved
    plugin and treats it as a loss while the engine is still mid-
    spray. The plugin's own timeout caps the wait, so a hung plugin
    can't stall the race.
    """
    plugin_name, af, route_type, src, dest = combo
    try:
        plugin = await node.traversal.attempt_plugin(
            src_map=src_map,
            dest_map=dest_map,
            sig_pipe=sig_pipe,
            plugin_name=plugin_name,
            af=af,
            route_type=route_type,
            src=src,
            dest=dest,
        )
    except asyncio.CancelledError:  # pylint: disable=try-except-raise
        raise
    except (ValueError, OSError, ConnectionError):
        log_exception()
        return None
    if plugin is None or plugin.result.done():
        return plugin
    try:
        await asyncio.wait_for(plugin.result, timeout=plugin.timeout)
    except asyncio.TimeoutError:
        log("attempt_one_combo: plugin.result timed out for {0}".format(plugin_name))
    except asyncio.CancelledError:
        raise
    except Exception:  # pylint: disable=broad-except
        # Plugin-side failure -- race_combos sees it via plugin_pipe
        # returning None on the unresolved future.
        log_exception()
    return plugin


def plugin_pipe(plugin):
    """Return the resolved pipe from a finished plugin, or None."""
    if plugin is None:
        return None
    fut = getattr(plugin, "result", None)
    if fut is None or not fut.done():
        return None
    try:
        return fut.result()
    except Exception:  # noqa: BLE001 -- failed plugin = None pipe
        return None


async def race_combos(
    node,
    sig_pipe,
    src_map,
    dest_map,
    combos,
    timeout,
):
    """Launch combos concurrently; return (pipe, winner_plugin) or (None, None).

    First non-None pipe wins. Outstanding tasks are cancelled, then drained,
    and every losing plugin is closed via close_plugin so its sockets are
    released before the next slot.
    """
    if not combos:
        return None, None

    tasks = [
        asyncio.ensure_future(
            attempt_one_combo(node, sig_pipe, src_map, dest_map, combo)
        )
        for combo in combos
    ]

    plugins = []
    winner_pipe = None
    winner_plugin = None
    try:
        for fut in asyncio.as_completed(tasks, timeout=timeout):
            try:
                plugin = await fut
            except asyncio.CancelledError:  # pylint: disable=try-except-raise
                raise
            except (asyncio.TimeoutError, OSError, ConnectionError, ValueError):
                log_exception()
                plugin = None
            except Exception:  # noqa: BLE001 -- log unexpected, treat as loss
                log_exception()
                plugin = None
            if plugin is None:
                continue
            plugins.append(plugin)
            pipe = plugin_pipe(plugin)
            if pipe is not None:
                winner_pipe = pipe
                winner_plugin = plugin
                break
    except asyncio.TimeoutError:
        # Whole-race ceiling hit -- no winner this round.
        pass
    except asyncio.CancelledError:
        for t in tasks:
            if not t.done():
                t.cancel()
        raise

    for t in tasks:
        if not t.done():
            t.cancel()
    late = await asyncio.gather(*tasks, return_exceptions=True)
    for item in late:
        if (
            item is not None
            and not isinstance(item, BaseException)
            and item is not winner_plugin
            and item not in plugins
        ):
            plugins.append(item)

    for p in plugins:
        if p is not winner_plugin:
            await close_plugin(p, node.traversal.plugins, node.traversal.inbound_pipes)

    return winner_pipe, winner_plugin


# ---------------------------------------------------------------------------
# Bipartite slot scheduling
# ---------------------------------------------------------------------------

def sort_nics_by_nat(nics):
    """Sort NIC info dicts by ``info["nat"]["type"]`` ascending.

    NICs without a parseable nat type are placed last so they don't crowd
    out NICs with a known easy classification.
    """
    sentinel = 1 << 30

    def key(info):
        nat = info.get("nat") if isinstance(info, dict) else None
        if isinstance(nat, dict) and "type" in nat:
            try:
                return int(nat["type"])
            except (TypeError, ValueError):
                return sentinel
        return sentinel

    return sorted(nics, key=key)


def round_robin_slots(
    src_nics,
    dest_nics,
):
    """Schedule every (src, dest) pair into matching-disjoint slots.

    Yields slots; each slot is a list of (src, dest) pairs in
    which no two pairs share a src NIC or a dest NIC. Slot 0 pairs by
    sorted index ((src[0], dest[0]), (src[1], dest[1]), ...) -- so the
    easiest NATs on each side meet first when the input lists are sorted
    by nat_type. Subsequent slots rotate the dest index so every (src,
    dest) combination appears exactly once across all yielded slots.

    For ``m = len(src_nics)``, ``n = len(dest_nics)`` the schedule has
    ``max(m, n)`` slots and ``min(m, n)`` parallel pairs per slot --
    which is the minimum possible (chromatic index of K(m,n)).
    """
    m = len(src_nics)
    n = len(dest_nics)
    if m == 0 or n == 0:
        return

    if m <= n:
        for k in range(n):
            slot = []
            for i in range(m):
                j = (i + k) % n
                slot.append((src_nics[i], dest_nics[j]))
            yield slot
    else:
        for k in range(m):
            slot = []
            for j in range(n):
                i = (j + k) % m
                slot.append((src_nics[i], dest_nics[j]))
            yield slot


def derive_sorted_nics(
    pairs,
):
    """Extract unique src and dest NICs from `pairs` and sort by nat_type."""
    src_seen = {}
    dest_seen = {}
    for s, d in pairs:
        src_seen.setdefault(id(s), s)
        dest_seen.setdefault(id(d), d)
    return (
        sort_nics_by_nat(src_seen.values()),
        sort_nics_by_nat(dest_seen.values()),
    )


# ---------------------------------------------------------------------------
# Phase implementations
# ---------------------------------------------------------------------------

async def phase1_direct(
    node,
    src_map,
    dest_map,
    sig_pipe,
    plugins,
):
    """Race direct_connect / reverse_connect across all valid combos."""
    names = [n for n in plugins_for_phase("direct") if n in plugins]
    if not names:
        return None, None

    loaders = node.traversal.plugin_loaders
    combos = []
    for af in (IP4, IP6):
        if not af_compatible(src_map, dest_map, af):
            continue
        for route_type in (NIC_BIND, LOOPBACK_BIND, EXT_BIND):
            for src, dest in viable_pairs_for_arc(
                af, route_type, src_map, dest_map,
            ):
                for name in names:
                    if name not in loaders:
                        continue
                    if not plugin_supports_route_type(loaders.get(name), route_type):
                        continue
                    combos.append((name, af, route_type, src, dest))

    if not combos:
        return None, None

    log(fstr(
        "auto_connect: phase1 racing {0} combos (budget={1}s)",
        (len(combos), PHASE1_BUDGET),
    ))
    return await race_combos(
        node, sig_pipe, src_map, dest_map, combos, PHASE1_BUDGET,
    )


async def punch_phase(
    node,
    src_map,
    dest_map,
    sig_pipe,
    plugin_names,
    label,
):
    """Generic phase-2/3 driver shared by tcp_punch and udp/probe.

    NIC_BIND sub-phase first, then EXT_BIND if NIC_BIND yielded nothing.
    Within a sub-phase, IP4 first then IP6, never concurrent. Per AF a
    bipartite schedule (sorted by nat_type) drives parallel attempts in
    each slot. plugin_names supplies the plugins raced concurrently
    against each scheduled (src, dest) pair.
    """
    loaders = node.traversal.plugin_loaders
    names = [n for n in plugin_names if n in loaders]
    if not names:
        return None, None

    for route_type in (NIC_BIND, EXT_BIND):
        active_names = [
            n for n in names
            if plugin_supports_route_type(loaders.get(n), route_type)
        ]
        if not active_names:
            continue

        slot_to = max(
            (plugin_timeout(loaders.get(n)) for n in active_names),
            default=DEFAULT_PLUGIN_TIMEOUT,
        )

        for af in (IP4, IP6):
            if not af_compatible(src_map, dest_map, af):
                continue
            pairs = viable_pairs_for_arc(af, route_type, src_map, dest_map)
            if not pairs:
                continue

            src_nics, dest_nics = derive_sorted_nics(pairs)
            allowed = {(id(s), id(d)) for s, d in pairs}

            for slot_idx, slot in enumerate(round_robin_slots(src_nics, dest_nics)):
                # Drop pairs the route_type filter rejected (e.g. equal
                # NIC IPs under NIC_BIND on same-machine cross-products).
                slot = [(s, d) for s, d in slot if (id(s), id(d)) in allowed]
                if not slot:
                    continue

                combos = []
                for src, dest in slot:
                    for name in active_names:
                        combos.append(
                            (name, af, route_type, src, dest)
                        )

                log(fstr(
                    "auto_connect: {0} route={1} af={2} slot={3} pairs={4} timeout={5}s",
                    (label, route_type, af, slot_idx, len(slot), slot_to),
                ))
                pipe, plugin = await race_combos(
                    node, sig_pipe, src_map, dest_map, combos, slot_to,
                )
                if pipe is not None:
                    return pipe, plugin

    return None, None


def addr_map_has_symmetric(addr_map):
    """True if any (af, nic) entry in addr_map has NAT type SYMMETRIC."""
    for af in (IP4, IP6):
        for entry in (addr_map.get(af) or {}).values():
            nat = entry.get("nat") or {}
            if nat.get("type") == SYMMETRIC_NAT:
                return True
    return False


async def phase2_tcp_punch(
    node,
    src_map,
    dest_map,
    sig_pipe,
    plugins,
):
    names = tuple(n for n in plugins_for_phase("punch") if n in plugins)
    if not names:
        return None, None
    # Skip tcp_punch entirely when either peer is behind a SYMMETRIC
    # NAT. The plugin's port-prediction math (boundary_port_alloc) is
    # built on EIM/EDM/preserving NAT behaviour where the next outbound
    # source-port is predictable. Symmetric NATs assign a fresh
    # external port per (src,dst) tuple, so the predicted ports never
    # match the peer's actual mappings -- every spray returns
    # successful=0/N. Without this skip, phase2 burns its full plugin
    # timeout (180 s) on a punch that's mathematically impossible.
    # Going straight to phase3 (where random_probe handles symmetric)
    # is strictly faster with no loss in success.
    if addr_map_has_symmetric(src_map) or addr_map_has_symmetric(dest_map):
        log("phase2_tcp_punch: SYMMETRIC NAT detected on at least one "
            "side; skipping tcp_punch (cannot predict ports)")
        return None, None
    # Skip tcp_punch when the destination is a Windows-XP listener
    # and we are not on the same machine. CLAUDE.md and pcap forensics
    # document an unfixable XP tcpip.sys behaviour: cross-machine
    # tcp_punch handshakes complete on the wire in full but XP
    # unilaterally RSTs the connection ~140ms after the final ACK.
    # The engine reports success but every echo round-trip dies. The
    # only way to make TCP simul-open work on XP is via a kernel-mode
    # NDIS filter that bypasses tcpip.sys entirely (Hamachi did this
    # in the XP era); not reachable from a Python library.
    # Same-LAN / same-machine paths win phase1_direct first so this
    # skip costs nothing on the LAN side; cross-internet just saves
    # the 180s plugin timeout that would never converge anyway.
    dest_os = (dest_map or {}).get("os") or ""
    if dest_os.startswith("Windows-XP") and not is_same_machine(src_map, dest_map):
        log("phase2_tcp_punch: dest is Windows-XP cross-machine; "
            "skipping (tcpip.sys simul-open RST is unfixable on XP)")
        return None, None
    return await punch_phase(
        node, src_map, dest_map, sig_pipe,
        plugin_names=names,
        label="phase2",
    )


async def phase3_udp_probe(
    node,
    src_map,
    dest_map,
    sig_pipe,
    plugins,
):
    names = tuple(n for n in plugins_for_phase("spray") if n in plugins)
    if not names:
        return None, None

    # The "never run two punches against the same dest concurrently"
    # rule applies here too: udp_punch and random_probe both fire UDP
    # sprays from the same NIC at the same dest, so racing them in
    # parallel causes (a) bind contention on local ephemeral ports
    # (random_probe takes 256, udp_punch tries 16 boundary buckets),
    # (b) recv-buffer pressure on the peer's NIC, and (c) extra
    # cross-magic frames each plugin's filter has to discard. Pick
    # one based on NAT shape: random_probe is the only plugin that
    # works when either peer is symmetric, so use it then; otherwise
    # udp_punch is the predictable-NAT optimised path.
    if addr_map_has_symmetric(src_map) or addr_map_has_symmetric(dest_map):
        chosen = "random_probe" if "random_probe" in names else names[0]
    else:
        chosen = "udp_punch" if "udp_punch" in names else names[0]
    log("phase3_udp_probe: chose plugin={0} from {1}".format(chosen, names))
    return await punch_phase(
        node, src_map, dest_map, sig_pipe,
        plugin_names=(chosen,),
        label="phase3",
    )


async def phase4_turn(
    node,
    src_map,
    dest_map,
    sig_pipe,
    plugins,
    cap=TURN_TOTAL_CAP,
):
    """Sequential TURN attempts, cap total attempts.

    Iterate AFs (IP4 then IP6). For each AF, walk our NICs in nat_type
    order. Pick the first dest NIC with which we form a valid
    EXT_BIND pair and that we haven't paired with yet. Fall back to a
    previously-used dest NIC only if every fresh option is invalid.
    Stop as soon as we hit `cap` total attempts.
    """
    relay_names = [n for n in plugins_for_phase("relay") if n in plugins]
    if not relay_names:
        return None, None
    # Phase 4 is single-plugin sequential. If multiple relay plugins
    # exist in the registry they'd need a different scheduler; for now
    # pick the first registered one.
    relay_name = relay_names[0]
    if relay_name not in node.traversal.plugin_loaders:
        return None, None
    loader = node.traversal.plugin_loaders[relay_name]
    if not plugin_supports_route_type(loader, EXT_BIND):
        return None, None

    timeout = plugin_timeout(loader)
    attempts = 0

    for af in (IP4, IP6):
        if attempts >= cap:
            break
        if not af_compatible(src_map, dest_map, af):
            continue
        pairs = viable_pairs_for_arc(af, EXT_BIND, src_map, dest_map)
        if not pairs:
            continue

        src_nics, dest_nics = derive_sorted_nics(pairs)
        allowed = {(id(s), id(d)) for s, d in pairs}
        used_dests = set()

        for src in src_nics:
            if attempts >= cap:
                break

            chosen = None
            for dest in dest_nics:
                if id(dest) in used_dests:
                    continue
                if (id(src), id(dest)) in allowed:
                    chosen = dest
                    break
            if chosen is None:
                for dest in dest_nics:
                    if (id(src), id(dest)) in allowed:
                        chosen = dest
                        break
            if chosen is None:
                continue

            used_dests.add(id(chosen))
            attempts += 1
            log(fstr(
                "auto_connect: phase4 turn af={0} attempt={1}/{2}",
                (af, attempts, cap),
            ))
            pipe, plugin = await race_combos(
                node, sig_pipe, src_map, dest_map,
                [(relay_name, af, EXT_BIND, src, chosen)],
                timeout,
            )
            if pipe is not None:
                return pipe, plugin

    return None, None


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

async def auto_connect(
    node,
    dest_addr,
    protocol=TCP,
    plugins=None,
    test_all_phases=False,
    afs=None,
):
    """Establish a P2P connection to dest_addr without picking a plugin.

    `protocol` controls which transport the returned pipe will use. Default
    is TCP so callers can rely on stream semantics without thinking about
    which plugin won. Pass `protocol=UDP` for a datagram pipe, or
    `protocol=None` to allow any plugin (mixed-transport caller — be ready
    to handle either pipe shape).

    `plugins` is the power-user override: pass an explicit sequence of
    plugin names and the protocol filter is bypassed. A phase whose
    plugins are all absent from the resolved set is skipped entirely.

    `test_all_phases=True` is a diagnostic mode: every phase runs even
    after an earlier one already produced a pipe. Each phase's outcome
    is logged with an [AC-PHASE] prefix so you can grep cumulative
    behaviour (e.g. punch failing after direct's TIME_WAIT residue).
    The first winning pipe is what gets returned to the caller; later
    phases run for telemetry and any pipes they produce are closed
    via close_plugin so they don't leak.

    `afs` (default None = both IP4 and IP6) restricts the phases to
    the given iterable of address families. Pass ``[IP6]`` to test
    only the v6 path -- the v4 entries are stripped from src_map /
    dest_map before any phase runs, so af_compatible() naturally
    short-circuits the v4 branches inside each phase.

    Returns ``(pipe, plugin)`` on success, ``(None, None)`` on failure.
    """
    if plugins is None:
        plugins = plugins_for_protocol(protocol)
    plugin_set = frozenset(plugins)

    try:
        addr_bytes, dest_vk, _ = await resolve_pnp_addr(node, dest_addr)
        dest_map = parse_node_addr(addr_bytes)
    except (ValueError, OSError, ConnectionError, asyncio.TimeoutError):
        log_exception()
        return None, None
    if dest_vk:
        dest_map["vk"] = dest_vk

    enrich_addr_map_with_loopback(dest_map)

    try:
        sig_pipe = await node.router.pipe(
            dest_map["pub_key_hex"],
            use_cache=True,
            hint_brokers=dest_map.get("mqtt_brokers") or [],
        )
    except (OSError, ConnectionError, asyncio.TimeoutError):
        log_exception()
        return None, None

    src_map = node.addr_map

    if afs is not None:
        # Diagnostic / power-user override: pin the cascade to a
        # specific AF or AF set by stripping the others off the addr
        # maps. Phase loops iterate (IP4, IP6) and call
        # af_compatible(src_map, dest_map, af) which returns False
        # when one side is empty -- so a v6-only run produces only
        # v6 combos and the v4 branches are no-ops.
        keep = set(afs)
        src_map = {k: v for k, v in src_map.items() if k not in (IP4, IP6) or k in keep}
        dest_map = {k: v for k, v in dest_map.items() if k not in (IP4, IP6) or k in keep}

    winner_pipe = None
    winner_plugin = None
    for phase_fn in (
        phase1_direct,
        phase2_tcp_punch,
        phase3_udp_probe,
        phase4_turn,
    ):
        pipe, plugin = await phase_fn(node, src_map, dest_map, sig_pipe, plugin_set)
        if test_all_phases:
            line = "[AC-PHASE] {0} -> pipe={1} plugin={2}".format(
                phase_fn.__name__,
                pipe is not None,
                getattr(plugin, "name", type(plugin).__name__) if plugin is not None else None,
            )
            log(line)
            print(line, flush=True)
            if pipe is not None and winner_pipe is None:
                winner_pipe = pipe
                winner_plugin = plugin
            elif pipe is not None:
                # Already have a winner -- close this later phase's pipe
                # so it doesn't leak. close_plugin is the canonical
                # cleanup path; safe to call on already-closed plugins.
                try:
                    await close_plugin(
                        plugin, node.traversal.plugins, node.traversal.inbound_pipes,
                    )
                except (OSError, asyncio.TimeoutError):
                    log_exception()
            continue
        if pipe is not None:
            return pipe, plugin

    if test_all_phases:
        return winner_pipe, winner_plugin
    return None, None
