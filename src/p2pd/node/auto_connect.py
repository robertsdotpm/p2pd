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
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
import asyncio
from aionetiface import (
    IP4, IP6, NIC_BIND, EXT_BIND, LOOPBACK_BIND, TCP, UDP,
    fstr, log, log_exception, parse_node_addr,
)
from .node_connect import resolve_pnp_addr
from .node_utils import enrich_addr_map_with_loopback
from ..traversal.traversal_utils import close_plugin


PHASE1_PLUGINS = ("direct_connect", "reverse_connect")
PHASE2_PLUGINS = ("tcp_punch",)
PHASE3_PLUGINS = ("udp_punch", "random_probe")
PHASE4_PLUGINS = ("turn",)

# Plugin sets by transport.
TCP_PLUGINS = ("direct_connect", "reverse_connect", "tcp_punch")
UDP_PLUGINS = ("udp_punch", "random_probe", "turn")

# Default rolls every plugin -- callers that pass plugins= explicitly
# get exactly that set, with no transport filtering. The default
# protocol on auto_connect is TCP, see plugins_for_protocol.
DEFAULT_PLUGINS = TCP_PLUGINS + UDP_PLUGINS


def plugins_for_protocol(protocol):
    """Return the default plugin set for a transport.

    `protocol=TCP` -- only stream plugins (direct_connect, reverse_connect,
                      tcp_punch). The returned pipe has TCP semantics.
    `protocol=UDP` -- only datagram plugins (udp_punch, random_probe, turn).
                      The returned pipe has UDP semantics.
    `protocol=None` -- every plugin in DEFAULT_PLUGINS, mixed transport.
                       Caller must be ready to handle either pipe shape.
    """
    if protocol == TCP:
        return TCP_PLUGINS
    if protocol == UDP:
        return UDP_PLUGINS
    if protocol is None:
        return DEFAULT_PLUGINS
    raise ValueError("protocol must be TCP, UDP, or None")

PHASE1_BUDGET = 3.0
TURN_TOTAL_CAP = 3
DEFAULT_PLUGIN_TIMEOUT = 25.0


# ---------------------------------------------------------------------------
# Pair filtering primitives
# ---------------------------------------------------------------------------

def af_compatible(src_map: Dict[str, Any], dest_map: Dict[str, Any], af: Any) -> bool:
    """True if both nodes have at least one interface for this address family."""
    return bool(src_map.get(af)) and bool(dest_map.get(af))


def pair_distinct(route_type: Any, src_info: Dict[str, Any], dest_info: Dict[str, Any]) -> bool:
    """Per-pair validity for a route type.

    NIC_BIND      different NIC IPs (otherwise bind/connect collide)
    LOOPBACK_BIND both sides advertise a loopback alias (different by
                  construction since alias is per-pubkey)
    EXT_BIND      different external IPs (otherwise connect loops
                  through the router back to the local stack)
    """
    if route_type == NIC_BIND:
        return int(src_info["nic"]) != int(dest_info["nic"])
    if route_type == LOOPBACK_BIND:
        return (
            src_info.get("loopback") is not None
            and dest_info.get("loopback") is not None
        )
    if route_type == EXT_BIND:
        return int(src_info["ext"]) != int(dest_info["ext"])
    return True


def is_same_machine(src_map: Dict[str, Any], dest_map: Dict[str, Any]) -> bool:
    """True if both addr_maps belong to the same physical host."""
    sid = src_map.get("machine_id")
    did = dest_map.get("machine_id")
    return bool(sid) and sid == did


def viable_pairs_for_arc(
    af: Any,
    route_type: Any,
    src_map: Dict[str, Any],
    dest_map: Dict[str, Any],
) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """Ordered (src_info, dest_info) pairs that survive per-pair filtering.

    Different-machine peers: restricted to matching-if_index pairs (alice's
    NIC0 may not have a route to bob's NIC1's subnet across NATs).

    Same-machine peers: emit the cross-product. Both nodes' NICs share one
    kernel routing table so dest_info["nic"] is reachable from any src NIC
    via the local stack. Matching-if_index pairs come first so direct
    in-subnet paths are tried before cross-subnet local routing.
    """
    src_af = src_map.get(af, {}) or {}
    dest_af = dest_map.get(af, {}) or {}
    if not src_af or not dest_af:
        return []

    same_machine = is_same_machine(src_map, dest_map)

    pairs = []
    seen = set()

    for if_idx, dest_info in dest_af.items():
        src_info = src_af.get(if_idx)
        if src_info is None:
            continue
        if pair_distinct(route_type, src_info, dest_info):
            seen.add((id(src_info), id(dest_info)))
            pairs.append((src_info, dest_info))

    if same_machine:
        for src_info in src_af.values():
            for dest_info in dest_af.values():
                key = (id(src_info), id(dest_info))
                if key in seen:
                    continue
                if pair_distinct(route_type, src_info, dest_info):
                    pairs.append((src_info, dest_info))

    return pairs


def plugin_supports_route_type(loader: Any, route_type: Any) -> bool:
    """True if the plugin loader's class accepts this route_type.

    Reads ``SUPPORTED_ROUTE_TYPES`` off the loader's plugin class
    (default: every route_type allowed).
    """
    if loader is None:
        return True
    cls = loader.get("class") if isinstance(loader, dict) else None
    if cls is None:
        return True
    supported = getattr(cls, "SUPPORTED_ROUTE_TYPES", None)
    if supported is None:
        return True
    return route_type in supported


def plugin_timeout(loader: Any) -> float:
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
    node: Any,
    sig_pipe: Any,
    src_map: Dict[str, Any],
    dest_map: Dict[str, Any],
    combo: Tuple[str, Any, Any, Dict[str, Any], Dict[str, Any]],
) -> Optional[Any]:
    """Run one (plugin, af, route_type, src_info, dest_info) attempt to completion."""
    plugin_name, af, route_type, src_info, dest_info = combo
    try:
        return await node.traversal.attempt_plugin(
            src_map=src_map,
            dest_map=dest_map,
            sig_pipe=sig_pipe,
            plugin_name=plugin_name,
            af=af,
            route_type=route_type,
            src_info=src_info,
            dest_info=dest_info,
        )
    except asyncio.CancelledError:  # pylint: disable=try-except-raise
        raise
    except (ValueError, OSError, ConnectionError):
        log_exception()
        return None


def plugin_pipe(plugin: Any) -> Optional[Any]:
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
    node: Any,
    sig_pipe: Any,
    src_map: Dict[str, Any],
    dest_map: Dict[str, Any],
    combos: Sequence[Tuple[str, Any, Any, Dict[str, Any], Dict[str, Any]]],
    timeout: float,
) -> Tuple[Optional[Any], Optional[Any]]:
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

def sort_nics_by_nat(nics: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
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
    src_nics: Sequence[Dict[str, Any]],
    dest_nics: Sequence[Dict[str, Any]],
) -> Iterable[List[Tuple[Dict[str, Any], Dict[str, Any]]]]:
    """Schedule every (src, dest) pair into matching-disjoint slots.

    Yields slots; each slot is a list of (src_info, dest_info) pairs in
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
    pairs: Sequence[Tuple[Dict[str, Any], Dict[str, Any]]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
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
    node: Any,
    src_map: Dict[str, Any],
    dest_map: Dict[str, Any],
    sig_pipe: Any,
    plugins: frozenset,
) -> Tuple[Optional[Any], Optional[Any]]:
    """Race direct_connect / reverse_connect across all valid combos."""
    names = [n for n in PHASE1_PLUGINS if n in plugins]
    if not names:
        return None, None

    loaders = node.traversal.plugin_loaders
    combos = []
    for af in (IP4, IP6):
        if not af_compatible(src_map, dest_map, af):
            continue
        for route_type in (NIC_BIND, LOOPBACK_BIND, EXT_BIND):
            for src_info, dest_info in viable_pairs_for_arc(
                af, route_type, src_map, dest_map,
            ):
                for name in names:
                    if name not in loaders:
                        continue
                    if not plugin_supports_route_type(loaders.get(name), route_type):
                        continue
                    combos.append((name, af, route_type, src_info, dest_info))

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
    node: Any,
    src_map: Dict[str, Any],
    dest_map: Dict[str, Any],
    sig_pipe: Any,
    plugin_names: Sequence[str],
    label: str,
) -> Tuple[Optional[Any], Optional[Any]]:
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
                for src_info, dest_info in slot:
                    for name in active_names:
                        combos.append(
                            (name, af, route_type, src_info, dest_info)
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


async def phase2_tcp_punch(
    node: Any,
    src_map: Dict[str, Any],
    dest_map: Dict[str, Any],
    sig_pipe: Any,
    plugins: frozenset,
) -> Tuple[Optional[Any], Optional[Any]]:
    if "tcp_punch" not in plugins:
        return None, None
    return await punch_phase(
        node, src_map, dest_map, sig_pipe,
        plugin_names=("tcp_punch",),
        label="phase2",
    )


async def phase3_udp_probe(
    node: Any,
    src_map: Dict[str, Any],
    dest_map: Dict[str, Any],
    sig_pipe: Any,
    plugins: frozenset,
) -> Tuple[Optional[Any], Optional[Any]]:
    names = tuple(n for n in PHASE3_PLUGINS if n in plugins)
    if not names:
        return None, None
    return await punch_phase(
        node, src_map, dest_map, sig_pipe,
        plugin_names=names,
        label="phase3",
    )


async def phase4_turn(
    node: Any,
    src_map: Dict[str, Any],
    dest_map: Dict[str, Any],
    sig_pipe: Any,
    plugins: frozenset,
    cap: int = TURN_TOTAL_CAP,
) -> Tuple[Optional[Any], Optional[Any]]:
    """Sequential TURN attempts, cap total attempts.

    Iterate AFs (IP4 then IP6). For each AF, walk our NICs in nat_type
    order. Pick the first dest NIC with which we form a valid
    EXT_BIND pair and that we haven't paired with yet. Fall back to a
    previously-used dest NIC only if every fresh option is invalid.
    Stop as soon as we hit `cap` total attempts.
    """
    if "turn" not in plugins or "turn" not in node.traversal.plugin_loaders:
        return None, None
    loader = node.traversal.plugin_loaders["turn"]
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

        for src_info in src_nics:
            if attempts >= cap:
                break

            chosen = None
            for dest_info in dest_nics:
                if id(dest_info) in used_dests:
                    continue
                if (id(src_info), id(dest_info)) in allowed:
                    chosen = dest_info
                    break
            if chosen is None:
                for dest_info in dest_nics:
                    if (id(src_info), id(dest_info)) in allowed:
                        chosen = dest_info
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
                [("turn", af, EXT_BIND, src_info, chosen)],
                timeout,
            )
            if pipe is not None:
                return pipe, plugin

    return None, None


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

async def auto_connect(
    node: Any,
    dest_addr: Any,
    protocol: Any = TCP,
    plugins: Optional[Sequence[str]] = None,
) -> Tuple[Optional[Any], Optional[Any]]:
    """Establish a P2P connection to dest_addr without picking a plugin.

    `protocol` controls which transport the returned pipe will use. Default
    is TCP so callers can rely on stream semantics without thinking about
    which plugin won. Pass `protocol=UDP` for a datagram pipe, or
    `protocol=None` to allow any plugin (mixed-transport caller — be ready
    to handle either pipe shape).

    `plugins` is the power-user override: pass an explicit sequence of
    plugin names and the protocol filter is bypassed. A phase whose
    plugins are all absent from the resolved set is skipped entirely.

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

    for phase_fn in (
        phase1_direct,
        phase2_tcp_punch,
        phase3_udp_probe,
        phase4_turn,
    ):
        pipe, plugin = await phase_fn(node, src_map, dest_map, sig_pipe, plugin_set)
        if pipe is not None:
            return pipe, plugin

    return None, None
