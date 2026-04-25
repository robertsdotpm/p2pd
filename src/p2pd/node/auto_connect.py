"""auto_connect: try installed plugins in batched per-pair rounds, fall back to TURN."""
from typing import Any, Dict, Iterable, List, Optional, Tuple
import asyncio
import random
from aionetiface import (
    IP4, IP6, NIC_BIND, EXT_BIND,
    fstr, log, log_exception, parse_node_addr,
)
from .node_connect import resolve_pnp_addr
from ..traversal.traversal_utils import close_plugin, get_if_infos_order


# Plugins that should never be tried in auto-mode: signaling-only or relay
SKIP_IN_AUTO = frozenset({"turn", "get_addr", "return_addr"})

# Default batching knobs. auto_connect kwargs override these.
DEFAULT_MAX_ROUNDS = 3
DEFAULT_PLUGIN_JITTER = 0.5    # max secs each plugin sleeps before its own work
DEFAULT_BATCH_JITTER = 1.0     # max secs slept between batches (skipped on round 0)


def af_compatible(src_map: Dict[str, Any], dest_map: Dict[str, Any], af: Any) -> bool:
    """True if both nodes have at least one interface for this address family."""
    return bool(src_map.get(af)) and bool(dest_map.get(af))


def pair_distinct(route_type: Any, src_info: Dict[str, Any], dest_info: Dict[str, Any]) -> bool:
    """Per-pair validity: NIC_BIND wants different NIC IPs, EXT_BIND different ext IPs.

    NIC_BIND with matching NIC IPs would mean two nodes claim the same local
    address; the bind/connect will collide. EXT_BIND with matching ext IPs
    means both nodes are behind the same WAN address — connecting to that
    external address loops back to the local stack.
    """
    if route_type == NIC_BIND:
        return int(src_info["nic"]) != int(dest_info["nic"])
    if route_type == EXT_BIND:
        return int(src_info["ext"]) != int(dest_info["ext"])
    return True


def has_valid_pair(
    src_map: Dict[str, Any],
    dest_map: Dict[str, Any],
    af: Any,
    route_type: Any,
) -> bool:
    """Return True if at least one matched-by-if_index pair has distinct addresses
    for the given route_type.

    NIC_BIND: requires different NIC IPs.
    EXT_BIND: requires different external IPs.
    Returns False if either AF dict is empty (no addresses to connect with).
    If neither dict is empty but no if_index is shared, optimistically allow it
    and let the per-pair filter in auto_combo_batches make the final call.
    """
    src_af = src_map.get(af)
    dest_af = dest_map.get(af)
    if not src_af or not dest_af:
        return False

    found_shared = False
    for if_idx, dest_info in dest_af.items():
        src_info = src_af.get(if_idx)
        if src_info is None:
            continue
        found_shared = True
        if pair_distinct(route_type, src_info, dest_info):
            return True
    return not found_shared


def viable_pairs_for_arc(
    af: Any,
    route_type: Any,
    src_map: Dict[str, Any],
    dest_map: Dict[str, Any],
) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """Ordered list of (src_info, dest_info) pairs that survive per-pair filtering.

    Order is taken from get_if_infos_order which puts overlap-first for
    NIC_BIND (LAN-style co-located peers) and unique-first for EXT_BIND
    (cross-NAT). Pairs that fail pair_distinct are dropped.
    """
    pairs = []
    for src_info, dest_info in get_if_infos_order(af, route_type, src_map, dest_map):
        if pair_distinct(route_type, src_info, dest_info):
            pairs.append((src_info, dest_info))
    return pairs


def auto_combos(
    node: Any,
    src_map: Dict[str, Any],
    dest_map: Dict[str, Any],
) -> List[Tuple[str, Any, Any, Dict[str, Any], Dict[str, Any]]]:
    """Flat per-pair combo list: [(plugin_name, af, route_type, src_info, dest_info), ...].

    A combo is included when:
      - the plugin is installed and not in SKIP_IN_AUTO
      - both nodes have addresses for the AF
      - the (src_info, dest_info) pair survives pair_distinct for the route_type

    NIC_BIND combos come before EXT_BIND combos (local paths tried first).
    Within each route_type, get_if_infos_order's priority is preserved.

    Kept for direct callers / unit tests; auto_connect itself uses the
    batched generator below.
    """
    names = [n for n in node.traversal.plugin_loaders if n not in SKIP_IN_AUTO]
    combos = []
    for af in (IP4, IP6):
        if not af_compatible(src_map, dest_map, af):
            continue
        for route_type in (NIC_BIND, EXT_BIND):
            for src_info, dest_info in viable_pairs_for_arc(af, route_type, src_map, dest_map):
                for name in names:
                    combos.append((name, af, route_type, src_info, dest_info))
    return combos


def auto_combo_batches(
    node: Any,
    src_map: Dict[str, Any],
    dest_map: Dict[str, Any],
    max_rounds: int = DEFAULT_MAX_ROUNDS,
) -> Iterable[List[Tuple[str, Any, Any, Dict[str, Any], Dict[str, Any]]]]:
    """Yield successive rounds of combos for auto_connect to race.

    Round k uses the k-th viable (src_info, dest_info) pair from each
    (af, route_type) arc. Within a round, every non-TURN plugin is paired
    with every (af, route_type, pair) so the batch contains the full plugin
    fan-out for that pair index.

    Bounded fan-out prevents thundering-herd on multi-homed hosts: a
    4-NIC × 4-NIC node would otherwise produce 16 × len(plugins) × len(arcs)
    racing plugins per call. With max_rounds=3 the cap is roughly
    3 × len(plugins) × len(arcs).
    """
    names = [n for n in node.traversal.plugin_loaders if n not in SKIP_IN_AUTO]
    if not names:
        return

    pairs_by_arc = {}
    for af in (IP4, IP6):
        if not af_compatible(src_map, dest_map, af):
            continue
        for route_type in (NIC_BIND, EXT_BIND):
            viable = viable_pairs_for_arc(af, route_type, src_map, dest_map)
            if viable:
                pairs_by_arc[(af, route_type)] = viable

    if not pairs_by_arc:
        return

    max_avail = max(len(v) for v in pairs_by_arc.values())
    rounds = min(max_rounds, max_avail)

    # Walk arcs in NIC_BIND-before-EXT_BIND order so each batch keeps the
    # local-paths-first ordering inside it.
    arc_order = []
    for af in (IP4, IP6):
        for route_type in (NIC_BIND, EXT_BIND):
            if (af, route_type) in pairs_by_arc:
                arc_order.append((af, route_type))

    for k in range(rounds):
        batch = []
        for (af, route_type) in arc_order:
            viable = pairs_by_arc[(af, route_type)]
            if k >= len(viable):
                continue
            src_info, dest_info = viable[k]
            for name in names:
                batch.append((name, af, route_type, src_info, dest_info))
        if batch:
            yield batch


async def staggered_attempt(
    node: Any,
    sig_pipe: Any,
    src_map: Dict[str, Any],
    dest_map: Dict[str, Any],
    combo: Tuple[str, Any, Any, Dict[str, Any], Dict[str, Any]],
    plugin_jitter: float,
) -> Optional[Any]:
    """Sleep up to plugin_jitter seconds, then attempt one plugin instance.

    Within-batch jitter avoids thundering-herd on the MQTT signal channel
    when many plugins in one batch all try to send their signaling burst at
    the exact same instant.
    """
    if plugin_jitter:
        await asyncio.sleep(random.uniform(0, plugin_jitter))
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


async def race_plugin_results(
    plugins: List[Any],
    timeout: float,
) -> Tuple[Optional[Any], Optional[Any]]:
    """Await all plugin.result futures concurrently via callbacks.

    Returns (pipe, winning_plugin) as soon as any plugin resolves its result
    to a non-None pipe. Returns (None, None) if all fail or timeout expires.

    Using add_done_callback instead of awaiting plugin.result directly means
    cancelling this coroutine does not cancel the underlying plugin futures —
    so background processes (e.g. punch subprocess) can still resolve them.
    """
    if not plugins:
        return None, None

    resolved = asyncio.Future()
    outstanding = [len(plugins)]

    def make_cb(plugin):
        def cb(fut):
            outstanding[0] -= 1
            if resolved.done():
                return
            try:
                pipe = fut.result()
            except Exception:
                pipe = None
            if pipe is not None:
                resolved.set_result((pipe, plugin))
            elif outstanding[0] <= 0:
                resolved.set_result(None)
        return cb

    for p in plugins:
        p.result.add_done_callback(make_cb(p))

    # When a future is already done at callback registration time, asyncio
    # schedules the callback for the NEXT event-loop iteration rather than
    # calling it synchronously. If every future was already done we must
    # yield control once so those callbacks actually fire before we check the
    # resolved state.
    if all(p.result.done() for p in plugins):
        await asyncio.sleep(0)

    if not resolved.done():
        remaining_count = sum(1 for p in plugins if not p.result.done())
        if remaining_count == 0:
            resolved.set_result(None)

    try:
        result = await asyncio.wait_for(asyncio.shield(resolved), timeout=timeout)
    except asyncio.TimeoutError:
        if not resolved.done():
            resolved.cancel()
        result = None

    if result is None:
        return None, None
    return result


async def turn_fallback(
    node: Any,
    src_map: Dict[str, Any],
    dest_map: Dict[str, Any],
    sig_pipe: Any,
    timeout: float,
    limit: int,
) -> Tuple[Optional[Any], Optional[Any]]:
    """Try the TURN relay plugin sequentially for up to `limit` (af, if-pair) combos.

    TURN requires different external IPs (EXT_BIND). We try AF=IP4 first, then
    IP6. Within each AF we walk the if_infos_order list and attempt one TURN
    session per pair, stopping as soon as one succeeds or we hit `limit`.

    TURN is a separate pathway from the auto_combo_batches loop — it is only
    consulted after every batch of direct/punch/reverse plugins has failed.
    """
    if "turn" not in node.traversal.plugin_loaders:
        return None, None

    from ..traversal.traversal_utils import get_if_infos_order

    count = 0
    for af in (IP4, IP6):
        if not af_compatible(src_map, dest_map, af):
            continue
        if not has_valid_pair(src_map, dest_map, af, EXT_BIND):
            continue

        if_pairs = get_if_infos_order(af, EXT_BIND, src_map, dest_map)
        same_machine = dest_map["machine_id"] == src_map["machine_id"]

        for src_info, dest_info in if_pairs:
            if count >= limit:
                return None, None
            count += 1

            plugin = None
            try:
                plugin = node.traversal.create_plugin(
                    af, EXT_BIND, src_info, dest_info, same_machine, "turn"
                )
                plugin.set_addrs(src_map, dest_map)
                plugin.sig_pipe = sig_pipe
                await node.traversal.run_plugin(plugin)

                pipe = await asyncio.wait_for(
                    asyncio.shield(plugin.result), timeout=timeout
                )
                if pipe is not None:
                    return pipe, plugin

            except asyncio.CancelledError:  # pylint: disable=try-except-raise
                raise
            except (ValueError, OSError, ConnectionError, asyncio.TimeoutError):
                log_exception()

            if plugin is not None:
                await close_plugin(
                    plugin, node.traversal.plugins, node.traversal.inbound_pipes
                )

    return None, None


def batch_timeout(node: Any, batch: List[Any]) -> float:
    """Per-batch race timeout: max plugin.timeout across plugins in the batch.

    A batch with punch (~50s) and direct_connect (~5s) waits for punch to
    reach its declared budget before declaring the batch a loss. Fast
    plugins that fail early just lose individually within the same race —
    the slowest plugin in the batch sets the ceiling.
    """
    loaders = node.traversal.plugin_loaders
    timeouts = []
    for combo in batch:
        plugin_name = combo[0]
        meta = loaders.get(plugin_name)
        if meta and "timeout" in meta:
            timeouts.append(meta["timeout"])
    if timeouts:
        return float(max(timeouts))
    # Conservative fallback if no per-plugin meta is available.
    return 25.0


async def auto_connect(
    node: Any,
    dest_addr: Any,
    timeout: float = 60.0,
    turn_limit: int = 3,
    max_rounds: int = DEFAULT_MAX_ROUNDS,
    plugin_jitter: float = DEFAULT_PLUGIN_JITTER,
    batch_jitter: float = DEFAULT_BATCH_JITTER,
) -> Tuple[Optional[Any], Optional[Any]]:
    """Establish a P2P connection to dest_addr without specifying a plugin manually.

    Strategy:
      1. Resolve dest_addr (accepts raw addr_bytes or a PNP nickname).
      2. Build successive batches of (plugin, af, route_type, src_info, dest_info)
         tuples, one batch per pair index. Round 0 uses the highest-priority
         pair from each (af, route_type) arc; round 1 the next; up to max_rounds.
      3. For each batch, launch every combo concurrently with optional
         within-batch start jitter, then race their results. The first
         non-None pipe wins.
      4. If all batches fail, fall back to TURN (a separate pathway, never
         interleaved with the direct/punch/reverse plugins above).

    `timeout` sets the TURN fallback per-pair timeout. Each batch in step 3
    uses its own per-batch timeout derived from the slowest plugin in the
    batch (see batch_timeout).
    """
    # --- 1. Resolve destination ---
    try:
        addr_bytes, dest_vk, _ = await resolve_pnp_addr(node, dest_addr)
        dest_map = parse_node_addr(addr_bytes)
    except (ValueError, OSError, ConnectionError, asyncio.TimeoutError):
        log_exception()
        return None, None
    if dest_vk:
        dest_map["vk"] = dest_vk

    try:
        sig_pipe = await node.router.pipe(dest_map["pub_key_hex"], use_cache=True)
    except (OSError, ConnectionError, asyncio.TimeoutError):
        log_exception()
        return None, None
    src_map = node.addr_map

    # --- 2 + 3. Batched fan-out across direct/punch/reverse plugins ---
    batches = list(auto_combo_batches(node, src_map, dest_map, max_rounds=max_rounds))
    log(fstr(
        "auto_connect: {0} batches for {1}",
        (len(batches), dest_addr),
    ))

    for batch_idx, batch in enumerate(batches):
        if batch_idx > 0 and batch_jitter:
            await asyncio.sleep(random.uniform(0, batch_jitter))

        # Launch every combo in this batch concurrently. attempt_plugin
        # awaits the underlying plugin.run() to completion, so each task
        # resolves with a finalised plugin (success / failure / timeout).
        attempt_tasks = [
            asyncio.ensure_future(
                staggered_attempt(node, sig_pipe, src_map, dest_map, combo, plugin_jitter)
            )
            for combo in batch
        ]

        # Race for the first non-None pipe instead of awaiting all attempts.
        # as_completed yields tasks in finish-order; the moment one completes
        # with a viable plugin we break and cancel the rest, so a fast
        # direct_connect doesn't get stalled waiting for a slow punch in the
        # same batch.
        winner_pipe = None
        winner_plugin = None
        plugins = []
        batch_to = batch_timeout(node, batch)
        try:
            for fut in asyncio.as_completed(attempt_tasks, timeout=batch_to):
                try:
                    plugin = await fut
                except asyncio.CancelledError:  # pylint: disable=try-except-raise
                    raise
                except (asyncio.TimeoutError, OSError, ConnectionError, ValueError):
                    plugin = None
                except Exception:  # noqa: BLE001 -- staggered_attempt logs unexpected paths
                    log_exception()
                    plugin = None
                if plugin is None:
                    continue
                plugins.append(plugin)
                if plugin.result.done():
                    try:
                        pipe = plugin.result.result()
                    except Exception:  # noqa: BLE001
                        pipe = None
                    if pipe is not None:
                        winner_pipe = pipe
                        winner_plugin = plugin
                        break
        except asyncio.TimeoutError:
            # Whole-batch ceiling hit — no winner. Fall through to cleanup
            # and the next batch (or TURN fallback).
            pass
        except asyncio.CancelledError:
            for t in attempt_tasks:
                if not t.done():
                    t.cancel()
            raise

        # Cancel any attempts still running — first-winner short-circuits as
        # soon as a viable pipe arrives, so we must reap the rest.
        for t in attempt_tasks:
            if not t.done():
                t.cancel()
        # Drain cancellations + collect any plugin objects that the cancelled
        # tasks managed to create before being killed, so we can close them.
        late = await asyncio.gather(*attempt_tasks, return_exceptions=True)
        for item in late:
            if (
                item is not None
                and not isinstance(item, BaseException)
                and item is not winner_plugin
                and item not in plugins
            ):
                plugins.append(item)

        # Close every plugin in this batch except the winner.
        for p in plugins:
            if p is not winner_plugin:
                await close_plugin(p, node.traversal.plugins, node.traversal.inbound_pipes)

        if winner_pipe is not None:
            return winner_pipe, winner_plugin

    # --- 4. TURN fallback (separate pathway, last resort) ---
    return await turn_fallback(
        node, src_map, dest_map, sig_pipe, timeout, turn_limit,
    )
