"""Utilities for the simple TCP selector punch engine."""
from typing import Any, List, Optional, Tuple
import socket
import time
from aionetiface import fstr, log, log_exception
from aionetiface.net.bind.bind_rules import binder_sync
from aionetiface.net.net_utils import ip_strip_if
from aionetiface.net.socket import apply_nic_pin_sockopts

"""
These magic sock options are required for TCP hole punching on
different operating systems.
"""


def sock_opt_voodoo(s: Any) -> None:
    """Apply non-blocking mode and SO_REUSEADDR/SO_REUSEPORT socket options for hole punching."""
    s.setblocking(False)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Windows' Python socket module has no SO_REUSEPORT attribute at all
    # (raising AttributeError before setsockopt is even called), while some
    # Unixes have the attribute but reject it at runtime (OSError). Both
    # cases are non-fatal here -- punch works without REUSEPORT on platforms
    # that don't support it.
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass

    """
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_SYNCNT, 2)
    except Exception:
        pass
    """


def bind_punch_sockets(
    af: Any,
    nic_id: Optional[str],
    port_allocs: List[Any],
    src_ip: Optional[str] = None,
    sock_type: int = socket.SOCK_STREAM,
    route: Optional[Any] = None,
) -> List[Tuple[Any, Any]]:
    """Create and bind one socket per port allocation; returns (alloc, sock) pairs.

    Shared by tcp_punch (sock_type=SOCK_STREAM, default) and udp_punch
    (sock_type=SOCK_DGRAM). The socket-opt voodoo, binder_sync call,
    and per-alloc collision handling are identical for both protocols
    so we have one implementation, not two.

    When route is provided, apply_nic_pin_sockopts pins each socket to
    route.interface so egress and bound source agree on multi-NIC
    hosts (LAN + cellular, multi-homed corporate). Without it the
    kernel may pick a different NIC than the one whose IP we bound
    to, the peer sees punch packets from an unexpected external IP,
    and CONFIRMs land on whichever socket happens to have a NAT
    mapping -- typically the demo's main listener, not the engine's
    bound socket.
    """
    if src_ip:
        bind_ip = src_ip
    else:
        bind_ip = "0.0.0.0" if af == socket.AF_INET else "::"

    bound_socks = []
    bind_failures = []
    for p in port_allocs:
        s = socket.socket(af, sock_type)
        sock_opt_voodoo(s)
        apply_nic_pin_sockopts(s, route)
        # Bump the receive buffer for UDP punch sockets so back-to-back
        # PROBE arrival across N spray rounds doesn't overflow the
        # default 64 KB Windows socket buffer. Matrix data showed the
        # connector receiving only 1 of ~18 expected PROBEs under
        # load; a fatter buffer absorbs the burst even when the
        # asyncio executor thread is briefly starved. Best-effort:
        # the kernel may cap below what we ask for and that's fine.
        if sock_type == socket.SOCK_DGRAM:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256 * 1024)
            except OSError:
                pass
        bind_tup = binder_sync(af, ip_strip_if(bind_ip), p.src_port, nic_id)
        try:
            s.bind(bind_tup)
            bound_socks.append((p, s))
        except OSError as exc:
            # Port collision (typically with the demo's main listener
            # at 10001 / the OS-picked secondary port) means the engine
            # silently loses that allocation. Log it so a "punch
            # converged but echo never came back" failure can be
            # traced to the actual bind that failed -- otherwise the
            # engine just runs with fewer sockets and no diagnostic.
            bind_failures.append((bind_tup, repr(exc)))
            s.close()

    if bind_failures:
        log(fstr(
            "bind_punch_sockets: {0}/{1} bind(s) FAILED on {2} (af={3} type={4})",
            (len(bind_failures), len(port_allocs), bind_ip, af,
             "DGRAM" if sock_type == socket.SOCK_DGRAM else "STREAM"),
        ))
        for bt, err in bind_failures:
            log(fstr("  bind {0} -> {1}", (bt, err)))
    log(fstr(
        "bind_punch_sockets: {0}/{1} bound on {2} (af={3} type={4})",
        (len(bound_socks), len(port_allocs), bind_ip, af,
         "DGRAM" if sock_type == socket.SOCK_DGRAM else "STREAM"),
    ))

    return bound_socks


def bind_tcp_sockets(
    af: Any,
    nic_id: Optional[str],
    port_allocs: List[Any],
    src_ip: Optional[str] = None,
    route: Optional[Any] = None,
) -> List[Tuple[Any, Any]]:
    """Create and bind one TCP socket per port allocation, returning successful (alloc, socket) pairs."""
    return bind_punch_sockets(
        af, nic_id, port_allocs, src_ip,
        sock_type=socket.SOCK_STREAM, route=route,
    )


def listen_on_tcp_sockets(bound_infos: List[Tuple[Any, Any]]) -> List[Tuple[Any, Any]]:
    """Call listen() on each bound socket, returning those that succeed."""
    listen_infos = []
    for bound_info in bound_infos:
        p, s = bound_info
        try:
            s.listen(1)
            listen_infos.append((p, s))
        except OSError:
            s.close()

    return listen_infos


def connect_on_tcp_sockets(same_machine: bool, bound_infos: List[Tuple[Any, Any]], dest_ip: str, spray_duration: float = 5.0) -> None:
    """
    Spray SYN packets at the destination for `spray_duration` seconds.

    spray_duration: how long to keep spraying (seconds).  The CLI default is
    5.0 s; FAST_PUNCH_PARAMS uses 2.0 s for LAN/protocol usage.
    """
    start = time.monotonic()
    end = start + spray_duration
    while time.monotonic() < end:
        for p, s in bound_infos:
            try:
                s.connect_ex((dest_ip, p.dest_port))
            except OSError:
                pass

        # High-frequency pressure keeps NAT mapping and races peer
        if not same_machine:
            # TODO -- what works best for WAN
            """
            0 -- yield to kernel
            n -- another micro value?
            x -- based on rtt?
            ?
            """
            time.sleep(0.01)  # 10ms is typical sweet spot


def sleep_until(punch_time: float, f_timer: Any, max_sleep: int = 10) -> None:
    """Block until punch_time (from f_timer()), sleeping at most max_sleep seconds."""
    now = f_timer()
    sleep_time = max(0, punch_time - now)

    # Cap sleep time to avoid large blocks if the host clock is far behind
    if sleep_time > max_sleep:
        sleep_time = max_sleep

    if sleep_time > 0:
        time.sleep(sleep_time)
