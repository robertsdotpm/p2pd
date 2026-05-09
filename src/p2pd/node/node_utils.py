"""Miscellaneous helpers for node startup and operation."""
from typing import Any, Dict, List, Optional, Tuple
import asyncio
import hashlib
import os
import socket
import signal
import time
from ecdsa import SigningKey, SECP256k1
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import pathlib
from aionetiface import (
    fstr, log, log_exception, ip_norm, get_aionetiface_install_root,
    get_n_stun_clients, TCP, RFC5389, IP4, IP6, IPR,
    async_wrap_errors, strip_none, sock_has_data, hash160, to_h, to_b, to_s,
    h_to_b, WebCurl, get_default_iface, USE_MAP_NO,
)
from aionetiface.nic.netifaces.netiface_extra import get_mac_address
from ..traversal.plugins.tcp_punch.punch_defs import PUNCH_CONF
from ..vendor.machine_id import hashed_machine_id


def resolve_install_path(conf: Dict[str, Any]) -> str:
    """Return the configured install path, falling back to the library root."""
    return conf["install_path"] or get_aionetiface_install_root()


def loopback_candidates_for(pub_key_hex: str, listen_port: int) -> List[Tuple[int, str, int]]:
    """Ordered list of (af, ip, port) loopback candidates for same-machine traversal.

    Listener tries each on bind (best-effort, ignores collisions); peer
    tries each on connect until one accepts. Order is "most-likely-to-
    work-without-collisions" first, "most-portable" second:

      1. (IP4, 127.X.Y.Z, listen_port)
         The per-node alias derived from pub_key. Unique address per node
         so two same-machine peers never collide on the same loopback IP.
         Doesn't work on platforms whose stack only routes 127.0.0.1
         (Windows XP has been observed to silently drop traffic here).

      2. (IP4, 127.0.0.1, listen_port)
         The universally-routable IPv4 loopback. listen_port is unique
         per node, so two same-machine peers don't collide on this
         tuple either. Used as the XP-safe primary fallback.

      3. (IP6, ::1, listen_port)
         IPv6 loopback. Works when the host has IPv6 enabled and the
         IPv4 stack is jammed (firewall, weird filter driver, etc.).

      4. (IP4, 127.0.0.1, pub_key_derived_port)
         Last-resort: pub_key-derived port in [30000, 60000) so two
         peers competing for the same listen_port still don't collide
         on this tuple. More likely to clash with unrelated services
         on the host but kept as a safety net.
    """
    primary_v4 = loopback_ip_for_node(pub_key_hex)
    val = int(pub_key_hex, 16)
    fallback_port = 30000 + (val % 30000)
    return [
        (IP4, primary_v4, listen_port),
        (IP4, "127.0.0.1", listen_port),
        (IP6, "::1", listen_port),
        (IP4, "127.0.0.1", fallback_port),
    ]


def enrich_addr_map_with_loopback(addr_map: Dict[str, Any]) -> Dict[str, Any]:
    """Attach the per-node loopback alias + candidate fallbacks to every if_info.

    parse_node_addr (in aionetiface) is intentionally unaware of the p2pd
    loopback convention; we add the field on the p2pd side after parse so
    select_dest_ipr can reach it as dest_info["loopback"] and the plugins
    can iterate dest_info["loopback_candidates"] on connect failure.
    Mutates and returns addr_map for the convenience of callers that
    want to chain.

    Only attaches when the addr_map advertises at least one IPv4
    interface -- the loopback fallbacks include IPv6 ::1, but for the
    same-machine path to make sense we still need at least one IP4
    if_info to anchor the loopback field on.
    """
    pub = addr_map.get("pub_key_hex")
    if not pub:
        return addr_map
    if not addr_map.get(IP4):
        return addr_map
    try:
        lo_str = loopback_ip_for_node(pub)
    except (ValueError, TypeError):
        return addr_map
    lo_ipr = IPR(lo_str)
    # The candidates list uses the if_info's own listen port (per_iface).
    # Different if_indexes on the same node may bind different ports, so
    # build the list per-info rather than once.
    for af in (IP4, IP6):
        af_dict = addr_map.get(af) or {}
        for info in af_dict.values():
            info["loopback"] = lo_ipr
            info_port = info.get("port")
            if info_port:
                try:
                    info["loopback_candidates"] = loopback_candidates_for(
                        pub, int(info_port)
                    )
                except (ValueError, TypeError):
                    info["loopback_candidates"] = []
            else:
                info["loopback_candidates"] = []
    return addr_map


def loopback_ip_for_node(pub_key_hex: str) -> str:
    """Deterministic 127.X.Y.Z loopback address keyed on a node's pub_key.

    Same-machine peers can't reliably TCP-connect between two of their own
    NIC IPs across different subnets on Windows — the kernel doesn't
    loopback-shortcut cross-subnet traffic. Both nodes instead bind a
    127.X.Y.Z address derived from their pub_key; the peer reads the same
    pub_key out of the addr_map and connects via the loopback interface,
    which always works.

    pub_key_hex is a node's compressed secp256k1 public key (66 hex chars),
    globally unique per node. Mapping it modulo the usable 127.0.0.0/8
    range keeps cross-node collisions effectively zero — and within one
    machine the two nodes guaranteed to differ since their key pairs do.

    Reserved corners are avoided:
      - First octet is always 127 (loopback).
      - Second octet (A) ∈ [1, 254] so 127.0.* / 127.255.* are skipped.
      - Last octet (C) ∈ [2, 254] so 127.A.B.0 / 127.A.B.1 / 127.A.B.255
        are skipped.

    The resulting address is bind-able and reachable on every supported
    platform: 127.0.0.0/8 is implicitly routed to the loopback iface by
    Linux and Windows alike, no admin-side route table change needed.
    """
    val = int(pub_key_hex, 16)
    # Available host addresses inside the 127.0.0.0/8 block after corner
    # exclusions: A∈[1,254] (254), B∈[0,255] (256), C∈[2,254] (253).
    c = 2 + (val % 253)
    val //= 253
    b = val % 256
    val //= 256
    a = 1 + (val % 254)
    return "127.{0}.{1}.{2}".format(a, b, c)


def make_stop_pair(existing: Optional[Any] = None) -> Tuple[Any, Any]:
    """Create a non-blocking/blocking socket pair used to signal shutdown, or return existing."""
    if existing:
        return existing
    stop_rw = socket.socketpair()
    stop_rw[0].setblocking(False)
    stop_rw[1].setblocking(True)
    return stop_rw


def pipe_future(inbound_pipes: Dict[str, Any], pipe_id: str) -> Any:
    """Return the Future for pipe_id, creating it if it does not yet exist."""
    if pipe_id not in inbound_pipes:
        inbound_pipes[pipe_id] = asyncio.Future()
    return inbound_pipes[pipe_id]


def pipe_ready(inbound_pipes: Dict[str, Any], pipe_id: str, pipe: Any) -> Any:
    """Resolve the Future for pipe_id with the given pipe object."""
    if pipe_id not in inbound_pipes:
        pipe_future(inbound_pipes, pipe_id)
    if not inbound_pipes[pipe_id].done():
        inbound_pipes[pipe_id].set_result(pipe)
    return pipe


def norm_listen_ips(listen_ips: List[str]) -> List[str]:
    """Deduplicate and sort a list of listen IPs, normalising each address."""
    # Skip if empty.
    if not listen_ips:
        return listen_ips

    # Norm the IPs.
    listen_ips = [ip_norm(ip) for ip in listen_ips]

    # Remove duplicates.
    listen_ips = list(set(listen_ips))

    # Sort it deterministically.
    listen_ips = sorted(listen_ips)

    return listen_ips


def load_signing_key(nics: List[Any], listen_ips: List[str], listen_port: int, install_path: str, node_name: Optional[str] = None) -> Tuple[SigningKey, bool]:
    """Load the node's ECDSA signing key from disk, generating and persisting a new one if absent.

    Returns (signing_key, is_fresh).  is_fresh=True means the key was
    generated this call (no prior file existed); is_fresh=False means
    it was loaded from disk.  Callers use this to distinguish first-
    time PNP registration (must check name is free) from re-registering
    a name we already own (skip the collision check).

    Identity is keyed by node_name. When node_name is None the file
    falls back to the single shared "default" path at install_path --
    suitable for single-node hosts and the common no-flag case. Two
    nodes that pass the same node_name share a private key: that's the
    contract, the caller is responsible for not booting two such nodes
    on the same box.

    nics / listen_ips / listen_port are kept in the function signature
    for backwards compatibility; they are no longer hashed into the path.
    Earlier schemes derived the path from (NIC names + listen_port) which
    churned every time the host's interfaces or DHCP-assigned addresses
    moved -- explicit node_name gives the caller stable, predictable
    identity instead.
    """
    # Make install dir if needed.
    pathlib.Path(install_path).mkdir(parents=True, exist_ok=True)

    name_tag = node_name if node_name else "default"
    # v3_ prefix distinguishes the explicit-node-name scheme from the
    # earlier (NIC, port)-hash and listen_ips-namespaced files.
    sk_path = os.path.realpath(
        os.path.join(install_path, fstr("PRIV_KEY_DONT_SHARE_v3_{0}.hex", (name_tag,)))
    )

    # Read existing key or generate fresh. We do NOT migrate forward
    # from old listen_ips-namespaced files: such migration can't tell
    # which (NIC, port) config a legacy file originated from, so two
    # nodes loading from the same install_path with distinct (NIC,
    # port) tuples would both adopt the same legacy key and end up
    # with identical pubkeys -- the exact regression the IPv6 churn
    # fix was meant to avoid in spirit. Users upgrading from the
    # legacy scheme get one fresh identity per (NIC, port); the old
    # files stay on disk untouched (the user can delete them once
    # the new identity is registered).
    if os.path.exists(sk_path):
        with open(sk_path, mode="r", encoding="utf-8") as fp:
            sk_hex = fp.read()
        is_fresh = False
    else:
        sk = SigningKey.generate(curve=SECP256k1)
        sk_buf = sk.to_string()
        sk_hex = to_h(sk_buf)
        with open(sk_path, "w", encoding="utf-8") as file:
            file.write(sk_hex)
        is_fresh = True

    # Convert secret key to a singing key.
    sk_buf = h_to_b(sk_hex)
    sk = SigningKey.from_string(sk_buf, curve=SECP256k1)
    return sk, is_fresh


async def fallback_machine_id(netifaces: Any, app_id: str = "p2pd") -> str:
    """Derive a stable machine ID from hostname, default interface name, and MAC address."""
    host = socket.gethostname()
    if_name = get_default_iface(netifaces)
    mac = await get_mac_address(if_name, netifaces)
    buf = fstr(
        "{0} {1} {2} {3}",
        (
            app_id,
            host,
            if_name,
            mac,
        ),
    )
    return to_s(hashlib.sha256(to_b(buf)).hexdigest())


async def close_idle_pipes(node: Any) -> None:
    """
    As the number of free processes in the process pool
    decreases and the pool approaches full the need to
    check for idle connections to free up processes becomes
    more urgent. The math below allocates an interval to use
    for the idle count down based on urgency (remaining
    processes) in reference to a min and max idle interval.
    """
    punch = getattr(node.resources, "punch_factory", None)
    if punch is None or punch.max_workers <= 0:
        return

    floor_check = 300
    ceil_check = 7200
    while not sock_has_data(node.stop_reader):
        alloc_pcent = punch.active_punchers / punch.max_workers
        num_space = ceil_check - floor_check
        abs_placement = ceil_check - (num_space * alloc_pcent)

        close_list = []
        cur_time = time.time()
        next_sleep = 5  # default max sleep

        # Sort recv queue oldest → newest
        node.resources.last_recv_queue.sort(
            key=lambda pipe: node.resources.last_recv_table.get(pipe.sock, 0)
        )

        # Loop over the queue
        for pipe in node.resources.last_recv_queue:
            last_recv = node.resources.last_recv_table.get(pipe.sock)
            if last_recv is None:
                continue

            elapsed = max(0, cur_time - last_recv)
            if elapsed >= abs_placement:
                close_list.append(pipe)
            else:
                # Compute time until this pipe reaches abs_placement
                time_until_expire = abs_placement - elapsed
                next_sleep = min(next_sleep, time_until_expire)
                # Queue is sorted, so no need to check further
                break

        # Close idle pipes
        for pipe in close_list:
            node.resources.last_recv_queue.remove(pipe)
            node.resources.last_recv_table.pop(pipe.sock, None)
            try:
                await asyncio.wait_for(pipe.close(), timeout=2)
            except asyncio.TimeoutError:
                log("close idle pipe close timeout")
            except (OSError, ConnectionError):
                log_exception()
                log("unknown exception for close pipe in close_idle_pipes.")

        # Sleep until the next pipe is due, capped at 5 seconds
        await asyncio.sleep(min(next_sleep, 5))


async def load_stun_clients(ifs: List[Any], limit: int = USE_MAP_NO) -> Dict[Any, Dict[int, List[Any]]]:
    """Concurrently load up to limit TCP STUN clients per AF per interface and return them indexed."""
    stun_clients = {IP4: {}, IP6: {}}
    tasks = []

    for if_index in range(len(ifs)):
        interface = ifs[if_index]
        for af in interface.supported():

            async def job(af: Any = af, if_index: int = if_index, interface: Any = interface) -> Tuple[Any, int, List[Any]]:
                """Fetch STUN clients for one (af, interface) pair and return them with their index."""
                clients = await get_n_stun_clients(
                    af=af,
                    n=limit,
                    mode=RFC5389,
                    interface=interface,
                    proto=TCP,
                    conf=PUNCH_CONF,
                )
                return (af, if_index, clients)

            tasks.append(asyncio.create_task(job()))

    results = await asyncio.gather(*tasks, return_exceptions=False)
    for af, if_index, clients in results:
        stun_clients[af][if_index] = clients

    return stun_clients


def worker_init() -> None:
    """
    This runs when each worker process starts.
    We tell the worker to ignore SIGINT.
    """
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    except (OSError, AttributeError):
        # Fallback for edge cases or embedded environments
        pass


async def get_pp_executors(workers: Optional[int] = None) -> Tuple[int, Optional[Any]]:
    """Create a ThreadPoolExecutor for tcp_punch's burst-send worker.

    Was ProcessPoolExecutor for "more accurate timing and isolating
    busy connection spam from main app." In practice the precision
    benefit was marginal -- punch's sub-second timing precision
    comes from socket-call latency, not from process isolation,
    and the GIL releases on every socket op anyway. The cost was
    real though: on Python 3.8 + Windows, ProcessPoolExecutor's
    queue-management thread routinely crashes with
    OSError [WinError 6] ("invalid handle") and BrokenPipeError
    [WinError 109] mid-poll, killing the punch task even though
    the worker subprocess is fine. Documented CPython bug
    (issue 39104, 41588). Switching to ThreadPoolExecutor
    sidesteps that entire mess. Same Executor interface so callers
    don't change.

    Future: if punch precision in production turns out to need
    process isolation after all, replace with one-shot
    multiprocessing.Process per call (no pool, no queue manager).
    """
    workers = workers or min(32, os.cpu_count() + 4)
    pp_executor = None
    try:
        # ThreadPoolExecutor doesn't need worker_init's SIGINT handler:
        # signals are delivered to the main thread only, so worker
        # threads don't see them. Skip the initializer entirely.
        pp_executor = ThreadPoolExecutor(max_workers=workers)
    except asyncio.CancelledError:  # pylint: disable=try-except-raise
        raise
    except (OSError, RuntimeError):
        log_exception()

    log("get_pp_executors: type={0} workers={1} executor={2}".format(
        type(pp_executor).__name__ if pp_executor else "None",
        workers,
        "OK" if pp_executor is not None else "FAILED",
    ))
    return workers, pp_executor


async def load_machine_id(app_id: str, netifaces: Any) -> str:
    """Return a hashed machine ID for app_id, falling back to a network-derived value on failure."""
    try:
        return hashed_machine_id(app_id)
    except asyncio.CancelledError:  # pylint: disable=try-except-raise
        raise
    except (OSError, ValueError):
        return await fallback_machine_id(netifaces, app_id)


async def soft_bind_and_listen(node: Any, route: Any, label: str) -> int:
    """Bind and add_listener for one route; log on failure, never raise.

    Returns the actual bound port on success, 0 on failure.
    When node.listen_port is non-zero (user-specified), a bind failure is
    a hard miss — no silent port=0 fallback — so the caller's nic_successes
    counter stays at zero and listen_on_ifs can raise loudly.
    """
    try:
        await route.bind(port=node.listen_port)
    except (OSError, ValueError, AssertionError) as exc:
        log(fstr("listen_on_ifs: bind failed for {0}: {1}", (label, exc)))
        return 0
    except asyncio.CancelledError:  # pylint: disable=try-except-raise
        raise

    try:
        result = await node.add_listener(TCP, route)
    except (OSError, ValueError, AssertionError) as exc:
        log(fstr("listen_on_ifs: add_listener failed for {0}: {1}", (label, exc)))
        return 0
    except asyncio.CancelledError:  # pylint: disable=try-except-raise
        raise

    if result is None:
        return 0
    return result[0]


async def bind_nic_v4(node: Any, nic_i: int, nic: Any) -> int:
    """Bind v4 listen_local on one NIC.  Returns bound port (0 = fail).

    Critical: a zero return contributes to the "every NIC bind failed"
    runtime error in listen_on_ifs.
    """
    try:
        listed = await node.listen_local(TCP, node.listen_port, nic) or []
    except (OSError, ValueError, AssertionError) as exc:
        log(fstr("listen_on_ifs: listen_local nic={0} failed: {1}", (nic.id, exc)))
        return 0

    if not listed:
        return 0

    first = next((x for x in listed if isinstance(x, tuple) and x[0]), None)
    if not first:
        return 0
    nic_port = first[0]

    if not any(x is not None for x in listed):
        return 0

    node.if_ports[(IP4, nic_i)] = {"ext": nic_port, "nic": nic_port}
    node.if_ports.setdefault((IP6, nic_i), {})["nic"] = nic_port
    return nic_port


async def bind_nic_v6_ext(node: Any, nic_i: int, nic: Any, label: str) -> int:
    """Bind v6 ext on one NIC.  Returns bound port (0 = fail).  Non-critical."""
    v6_route = nic.route(IP6)
    port = await soft_bind_and_listen(node, v6_route, label)
    if port > 0:
        node.if_ports.setdefault((IP6, nic_i), {})["ext"] = port
    return port


async def bind_loopback(node: Any, cand_af: int, cand_ip: str, cand_port: int, label: str) -> int:
    """Bind a per-node loopback alias.  Returns port (0 = fail).  Non-critical.

    Deepcopies the route because add_listener retains the reference; without
    a copy the next iteration's bind(ips=...) would mutate the previous
    listener's route in place.
    """
    import copy as copy_mod
    try:
        # Use Interface("default") rather than node.ifs[0] so the
        # listen socket isn't SO_BINDTODEVICE-pinned to a physical
        # NIC.  apply_nic_pin_sockopts pins to route.interface.name;
        # Interface("default")'s name is "default" which the kernel
        # rejects with ENODEV, leaving the socket unpinned -- which
        # is exactly what we want for a 127.x bind, since the kernel
        # routes loopback traffic via `lo` and a NIC-pinned listen
        # socket can't accept SYNs that arrive on lo.
        from aionetiface import Interface
        default_nic = await Interface("default")
        cand_route = default_nic.route(cand_af)
        await cand_route.bind(ips=cand_ip, port=cand_port)
        await node.add_listener(TCP, cand_route)
        log(fstr("listen_on_ifs: {0} bound af={1}", (label, cand_af)))
        return cand_port
    except (OSError, ValueError, AssertionError) as exc:
        log(fstr("listen_on_ifs: {0} bind failed: {1}", (label, exc)))
        return 0


async def listen_on_ifs(node: Any) -> None:
    """Bind TCP listeners on every NIC, v6 ext per NIC, and per-node loopback
    aliases -- all concurrently in a single gather.

    Failure semantics:
      - ANY NIC listen_local that fails => OSError (no real inbound path).
        node.listen_port-bound NIC binds are the only ones that serve real
        peers; if zero of them succeeded, the node is unreachable.
      - v6 ext bind failures           => log + continue (NIC v4 still works).
      - Loopback alias failures        => log + continue (loopback is convenience).

    When node.listen_port is 0, a probe socket pre-resolves an OS-assigned
    ephemeral port so every concurrent bind targets the same number -- this
    is what lets the loopback aliases publish a stable port without waiting
    on the NIC binds to latch one.  All binds run concurrently via
    asyncio.gather(return_exceptions=True); one slow / hung NIC never blocks
    any other.  No retries -- a failed bind is a failed bind, surface it.
    """
    node.if_ports = {}

    if node.listen_port == 0:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("", 0))
            node.listen_port = probe.getsockname()[1]

    nic_tasks = []  # critical: (label, coro)
    aux_tasks = []  # non-critical: (label, coro)

    if node.listen_ips:
        # Strict listen_ips path: bind only the IPs in listen_ips on the NICs that own them.
        listen_iprs = [IPR(ip) for ip in node.listen_ips]
        for nic in node.ifs:
            for nic_ipr in nic:
                if nic_ipr in listen_iprs:
                    label = fstr("listen_ip {0}", (nic_ipr,))
                    nic_tasks.append((label, soft_bind_and_listen(node, nic_ipr.route, label)))
    else:
        for nic_i, nic in enumerate(node.ifs):
            label = fstr("listen_local nic={0}", (nic.id,))
            nic_tasks.append((label, bind_nic_v4(node, nic_i, nic)))
            if IP6 in nic.supported():
                v6_label = fstr("v6 ext nic={0}", (nic.id,))
                aux_tasks.append((v6_label, bind_nic_v6_ext(node, nic_i, nic, v6_label)))

    try:
        candidates = loopback_candidates_for(node.kp.public_key_hex, node.listen_port)
    except Exception as exc:  # pylint: disable=broad-except
        candidates = []
        log(fstr("listen_on_ifs: loopback candidates compute failed: {0}", (exc,)))

    for cand_af, cand_ip, cand_port in candidates:
        cand_label = fstr("loopback {0}:{1}", (cand_ip, cand_port))
        aux_tasks.append((cand_label, bind_loopback(node, cand_af, cand_ip, cand_port, cand_label)))

    all_tasks = nic_tasks + aux_tasks
    results = await asyncio.gather(
        *(c for _, c in all_tasks),
        return_exceptions=True,
    )

    nic_successes = 0
    nic_failures = []
    for (label, _), r in zip(nic_tasks, results[: len(nic_tasks)]):
        if isinstance(r, int) and r > 0:
            nic_successes += 1
        else:
            nic_failures.append(label)
            if isinstance(r, BaseException) and not isinstance(r, asyncio.CancelledError):
                log(fstr("listen_on_ifs: {0} raised: {1}", (label, r)))

    for (label, _), r in zip(aux_tasks, results[len(nic_tasks):]):
        if isinstance(r, BaseException) and not isinstance(r, asyncio.CancelledError):
            log(fstr("listen_on_ifs: aux {0} raised: {1}", (label, r)))

    if nic_tasks and nic_successes == 0:
        msg = fstr(
            "listen_on_ifs: every NIC bind failed ({0}/{0}); "
            "node has no real inbound path. Failures: {1}",
            (len(nic_tasks), "; ".join(nic_failures) or "(no labels)"),
        )
        log(msg)
        raise OSError(msg)


async def remote_reachability_cb(reachability: Dict[Any, Dict[Any, Any]], _msg: Any, client_tup: Any, pipe: Any) -> None:
    """Mark the NIC as reachable when an inbound connection arrives from the known p2pd probe server."""
    try:
        p2pd_ips = (
            IPR("2607:5300:60:80b0::1", af=IP6),
            IPR("158.69.27.176", af=IP4),
        )
        client_ip = IPR(client_tup[0], af=pipe.route.af)
        if client_ip not in p2pd_ips:
            return
        nic = pipe.route.interface
        af = pipe.route.af
        if nic.id in reachability[af]:
            future = reachability[af][nic.id]
            if not future.done():
                future.set_result(True)
    except (OSError, ValueError, KeyError, AttributeError):
        log("unknown exception in reachability cb")
        log_exception()


async def forward(node: Any, port: int, reachability: Dict[Any, Dict[Any, Any]]) -> Tuple[List[Any], List[Any]]:
    """Run UPnP port forwarding for every NIC/AF and probe reachability, returning (forwarded, reachable) lists."""
    from ..traversal.plugins.upnp.main import port_forward as upnp_port_forward

    tasks = []
    for nic in node.ifs:
        for af in nic.supported():

            async def do_forward(af: Any = af, nic: Any = nic) -> Optional[List[Any]]:
                """Forward the listen port for one (af, nic) pair and return [af, nic.id] on success."""
                reachability[af][nic.id] = asyncio.Future()
                route = await nic.route(af).bind()
                src_ip = route.nic() if af == IP4 else route.ext()
                src_tup = (src_ip, port)
                ret = await upnp_port_forward(af, nic, port, src_tup, "p2pd")
                if ret:
                    return [af, nic.id]

            tasks.append(do_forward())

    forward_success = strip_none(await asyncio.gather(*tasks, return_exceptions=True))

    test_addr = {IP4: "158.69.27.176", IP6: "2607:5300:60:80b0::1"}

    async def reachability_test(af: Any, nic: Any) -> None:
        """Trigger the remote p2pd probe server to connect back to us on the forwarded port."""
        route = nic.route(af)
        curl = WebCurl((test_addr[af], 80), route, do_close=0)
        try:
            await curl.vars({"action": "hello", "proto": "tcp", "port": str(port)}).get(
                "/p2pd/net_debug.php"
            )
        except asyncio.TimeoutError:
            return None

    await asyncio.gather(
        *[reachability_test(af, nic) for nic in node.ifs for af in nic.supported()],
        return_exceptions=True,
    )

    await asyncio.sleep(2)

    reachable = [
        (af, nic_id)
        for af in (IP4, IP6)
        for nic_id in reachability[af]
        if reachability[af][nic_id].done()
    ]
    return forward_success, reachable
