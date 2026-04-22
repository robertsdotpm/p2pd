"""Miscellaneous helpers for node startup and operation."""
from typing import Any, Dict, List, Optional, Tuple
import asyncio
import hashlib
import os
import socket
import signal
import time
from ecdsa import SigningKey, SECP256k1
from concurrent.futures import ProcessPoolExecutor
import pathlib
from aionetiface import (
    fstr, log, log_exception, ip_norm, get_aionetiface_install_root,
    get_n_stun_clients, TCP, RFC5389, IP4, IP6, IPR,
    async_wrap_errors, strip_none, sock_has_data, hash160, to_h, to_b, to_s,
    h_to_b, WebCurl, get_default_iface, USE_MAP_NO,
)
from aionetiface.nic.netifaces.netiface_extra import get_mac_address
from ..traversal.plugins.punch.punch_defs import PUNCH_CONF
from ..vendor.machine_id import hashed_machine_id


def resolve_install_path(conf: Dict[str, Any]) -> str:
    """Return the configured install path, falling back to the library root."""
    return conf["install_path"] or get_aionetiface_install_root()


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


def load_signing_key(nics: List[Any], listen_ips: List[str], listen_port: int, install_path: str) -> SigningKey:
    """Load the node's ECDSA signing key from disk, generating and persisting a new one if absent."""
    # Make install dir if needed.
    pathlib.Path(install_path).mkdir(parents=True, exist_ok=True)

    # Store cryptographic random bytes here for ECDSA ident.
    listen_str = ",".join(listen_ips) + ":" + str(listen_port)
    nic_str = ";".join([n.name for n in nics])
    listen_hash = hash160(nic_str + ">" + listen_str)  # hex
    sk_path = os.path.realpath(
        os.path.join(install_path, fstr("PRIV_KEY_DONT_SHARE_{0}.hex", (listen_hash,)))
    )

    # Read existing key, or generate and persist a new one.
    if os.path.exists(sk_path):
        with open(sk_path, mode="r", encoding="utf-8") as fp:
            sk_hex = fp.read()
    else:
        sk = SigningKey.generate(curve=SECP256k1)
        sk_buf = sk.to_string()
        sk_hex = to_h(sk_buf)
        with open(sk_path, "w", encoding="utf-8") as file:
            file.write(sk_hex)

    # Convert secret key to a singing key.
    sk_buf = h_to_b(sk_hex)
    sk = SigningKey.from_string(sk_buf, curve=SECP256k1)
    return sk


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
    """Create a ProcessPoolExecutor with worker_init, returning (worker_count, executor_or_None)."""
    workers = workers or min(32, os.cpu_count() + 4)
    pp_executor = None
    # return 0, None
    try:
        import sys
        if sys.version_info >= (3, 7):
            pp_executor = ProcessPoolExecutor(max_workers=workers, initializer=worker_init)
        else:
            # Python < 3.7 has no initializer= on ProcessPoolExecutor.
            # Set SIG_IGN before fork so children inherit it, then restore
            # the parent's handler once the pool is created.
            old_sigint = signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                pp_executor = ProcessPoolExecutor(max_workers=workers)
            finally:
                signal.signal(signal.SIGINT, old_sigint)
    except asyncio.CancelledError:  # pylint: disable=try-except-raise
        raise
    except (OSError, RuntimeError):
        # Not all platforms have a working implementation of sem_open / semaphores.
        # Android is one such platform. It does support multiprocessing but
        # this semaphore feature is missing and will throw an error here.
        # In this case -- log the error and revert to using a single event loop.
        log_exception()

    return workers, pp_executor


async def load_machine_id(app_id: str, netifaces: Any) -> str:
    """Return a hashed machine ID for app_id, falling back to a network-derived value on failure."""
    try:
        return hashed_machine_id(app_id)
    except asyncio.CancelledError:  # pylint: disable=try-except-raise
        raise
    except (OSError, ValueError):
        return await fallback_machine_id(netifaces, app_id)


async def listen_on_ifs(node: Any) -> None:
    """Bind and start TCP listeners on all interfaces (or only the requested listen IPs)."""
    for nic in node.ifs:
        if node.listen_ips:
            listen_iprs = [IPR(ip) for ip in node.listen_ips]
            for nic_ipr in nic:
                if nic_ipr not in listen_iprs:
                    continue
                route = await nic_ipr.route.bind(port=node.listen_port)
                await async_wrap_errors(node.add_listener(TCP, route))
            continue

        await async_wrap_errors(node.listen_local(TCP, node.listen_port, nic))

        if IP6 in nic.supported():
            route = await nic.route(IP6).bind(port=node.listen_port)
            await async_wrap_errors(node.add_listener(TCP, route))


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
    tasks = []
    for nic in node.ifs:
        for af in nic.supported():

            async def do_forward(af: Any = af, nic: Any = nic) -> Optional[List[Any]]:
                """Forward the listen port for one (af, nic) pair and return [af, nic.id] on success."""
                reachability[af][nic.id] = asyncio.Future()
                route = await nic.route(af).bind()
                ret = await route.forward(port=port)
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
