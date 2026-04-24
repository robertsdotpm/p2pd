"""auto_connect: concurrently try all installed plugins, fall back to TURN."""
from typing import Any, Dict, List, Optional, Tuple
import asyncio
from aionetiface import (
    IP4, IP6, NIC_BIND, EXT_BIND,
    fstr, log, log_exception, parse_node_addr,
)
from .node_connect import resolve_pnp_addr
from ..traversal.traversal_utils import close_plugin


# Plugins that should never be tried in auto-mode: signaling-only or relay
SKIP_IN_AUTO = frozenset({"turn", "get_addr", "return_addr"})


def af_compatible(src_map: Dict[str, Any], dest_map: Dict[str, Any], af: Any) -> bool:
    """True if both nodes have at least one interface for this address family."""
    return bool(src_map.get(af)) and bool(dest_map.get(af))


def auto_combos(
    node: Any,
    src_map: Dict[str, Any],
    dest_map: Dict[str, Any],
) -> List[Tuple[str, Any, Any]]:
    """Return (plugin_name, af, route_type) triples compatible with the two endpoints.

    A combo is included when:
      - the plugin is installed and not in the skip list
      - both nodes have addresses for the AF
      - at least one matching if_index pair has distinct addresses for the route_type
        (NIC_BIND: different NIC IPs; EXT_BIND: different external IPs)

    NIC_BIND pairs are listed before EXT_BIND so local paths are tried first.
    """
    names = [n for n in node.traversal.plugin_loaders if n not in SKIP_IN_AUTO]
    combos = []
    for af in (IP4, IP6):
        if not af_compatible(src_map, dest_map, af):
            continue
        for route_type in (NIC_BIND, EXT_BIND):
            if not has_valid_pair(src_map, dest_map, af, route_type):
                continue
            for name in names:
                combos.append((name, af, route_type))
    return combos


def has_valid_pair(
    src_map: Dict[str, Any],
    dest_map: Dict[str, Any],
    af: Any,
    route_type: Any,
) -> bool:
    """Return True if at least one matched (src_info, dest_info) by if_index has
    distinct addresses for the given route_type.

    NIC_BIND: requires different NIC IPs (can't use same socket on same IP).
    EXT_BIND: requires different external IPs (different NATs / WAN addresses).
    If neither dict is empty but no if_index is shared, we optimistically allow it
    and let attempt_plugin handle pair selection.
    Returns False if either AF dict is empty (no addresses to connect with).
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
        if route_type == NIC_BIND:
            if int(dest_info["nic"]) != int(src_info["nic"]):
                return True
        elif route_type == EXT_BIND:
            if int(dest_info["ext"]) != int(src_info["ext"]):
                return True
    return not found_shared  # no shared if_index → let attempt_plugin decide


async def race_plugin_results(
    plugins: List[Any],
    timeout: float,
) -> Tuple[Optional[Any], Optional[Any]]:
    """Await all plugin.result futures concurrently via callbacks.

    Returns (pipe, winning_plugin) as soon as any plugin resolves its result
    to a non-None pipe.  Returns (None, None) if all fail or timeout expires.

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
    # calling it synchronously.  If every future was already done we must
    # yield control once so those callbacks actually fire before we check the
    # resolved state.  Without the yield the edge-case guard below would race
    # against unscheduled callbacks and set resolved=None prematurely.
    if all(p.result.done() for p in plugins):
        await asyncio.sleep(0)  # let scheduled callbacks run

    if not resolved.done():
        # True edge case: all were done but all had None/exception results.
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
    return result  # (pipe, plugin)


async def turn_fallback(
    node: Any,
    src_map: Dict[str, Any],
    dest_map: Dict[str, Any],
    sig_pipe: Any,
    timeout: float,
    limit: int,
) -> Tuple[Optional[Any], Optional[Any]]:
    """Try the TURN relay plugin sequentially for up to `limit` (af, if-pair) combos.

    TURN requires different external IPs (EXT_BIND).  We try AF=IP4 first, then
    IP6.  Within each AF we walk the if_infos_order list and attempt one TURN
    session per pair, stopping as soon as one succeeds or we hit `limit`.
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

            except asyncio.CancelledError:
                raise
            except (ValueError, OSError, ConnectionError, asyncio.TimeoutError):
                log_exception()

            if plugin is not None:
                await close_plugin(
                    plugin, node.traversal.plugins, node.traversal.inbound_pipes
                )

    return None, None


async def auto_connect(
    node: Any,
    dest_addr: Any,
    timeout: float = 60.0,
    turn_limit: int = 3,
) -> Tuple[Optional[Any], Optional[Any]]:
    """Establish a P2P connection to dest_addr without specifying a plugin manually.

    Strategy:
      1. Resolve dest_addr (accepts raw addr_bytes or a PNP nickname).
      2. Build every valid (plugin_name, af, route_type) combo:
           - non-TURN plugins only
           - AF supported by both nodes
           - at least one if-pair with distinct addresses for the route type
           - NIC_BIND (local) combos listed before EXT_BIND (WAN) combos
      3. Launch all combos — each call to attempt_plugin returns almost
         immediately after scheduling the plugin; the actual pipe arrives later
         via plugin.result.
      4. Race all plugin.result futures; return (pipe, plugin) for the first
         non-None winner and cancel / clean up the rest.
      5. If every concurrent attempt fails, try TURN sequentially up to
         turn_limit interface pairs (EXT_BIND only; different WAN IPs required).

    Returns (pipe, plugin) on success, (None, None) on total failure.
    """
    # --- 1. Resolve destination ---
    addr_bytes, dest_vk, _ = await resolve_pnp_addr(node, dest_addr)
    dest_map = parse_node_addr(addr_bytes)
    if dest_vk:
        dest_map["vk"] = dest_vk

    sig_pipe = await node.router.pipe(dest_map["pub_key_hex"], use_cache=True)
    src_map = node.addr_map

    # --- 2. Build combos ---
    combos = auto_combos(node, src_map, dest_map)
    log(fstr("auto_connect: {0} combos for {1}", (len(combos), dest_addr)))

    # --- 3. Launch plugins concurrently ---
    plugins = []
    for plugin_name, af, route_type in combos:
        try:
            plugin = await node.traversal.attempt_plugin(
                src_map=src_map,
                dest_map=dest_map,
                sig_pipe=sig_pipe,
                plugin_name=plugin_name,
                af=af,
                route_type=route_type,
            )
            if plugin is not None:
                plugins.append(plugin)
        except asyncio.CancelledError:
            raise
        except (ValueError, OSError, ConnectionError):
            log_exception()

    # --- 4. Race results ---
    winner_pipe, winner_plugin = await race_plugin_results(plugins, timeout)

    # Clean up losers regardless of outcome
    for p in plugins:
        if p is not winner_plugin:
            await close_plugin(p, node.traversal.plugins, node.traversal.inbound_pipes)

    if winner_pipe is not None:
        return winner_pipe, winner_plugin

    # --- 5. TURN fallback ---
    return await turn_fallback(
        node, src_map, dest_map, sig_pipe, timeout, turn_limit
    )
