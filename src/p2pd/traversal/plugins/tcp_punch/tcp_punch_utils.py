"""Utilities for the simple TCP selector punch engine."""
from typing import Any, List, Optional, Tuple
import socket
import struct
import sys
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
    """Apply non-blocking mode and the platform-correct address-reuse sockopt for hole punching.

    Windows: SO_REUSEADDR has the *opposite* semantics of POSIX -- it
    permits two sockets to share an exact 4-tuple, which lets a stray
    listener hijack our bound port and confuses the TCP state machine
    during simultaneous-open. SO_EXCLUSIVEADDRUSE is the Windows-correct
    flag: it tells the kernel "no other socket may steal this binding"
    so the simul-open SYN/SYN match converges unambiguously on our
    socket.

    POSIX: SO_REUSEADDR + SO_REUSEPORT (where available) are required
    so the engine can re-bind the predicted port across retries
    without hitting TIME_WAIT, and so multiple punch sockets can share
    the local port if needed.
    """
    s.setblocking(False)
    if sys.platform == "win32" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        except OSError:
            # Older Windows / restricted contexts may reject the flag.
            # Fall back to REUSEADDR so the bind still succeeds rather
            # than tearing down the engine.
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except OSError:
                pass
    else:
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
        # SO_LINGER {l_onoff=1, l_linger=0} on TCP punch sockets so close()
        # sends RST instead of FIN -- bypasses TIME_WAIT entirely. Without
        # this, Windows refuses to reuse the same 4-tuple for ~240 s and
        # logs Event 4227 ("selected local endpoint was recently used");
        # back-to-back punches in the same NTP bucket get blocked at the
        # kernel before the SYN ever leaves. Best-effort: ignore failures.
        if sock_type == socket.SOCK_STREAM:
            try:
                s.setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER,
                    struct.pack("ii", 1, 0),
                )
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

        # Pace the spray. 1 ms was effectively "fire as fast as the loop can"
        # which on Windows XP trips the half-open SYN cap (Tcpip Event 4226 --
        # default 10 concurrent half-opens). 50 ms gives the kernel time to
        # actually push each SYN out and drain the half-open queue between
        # rounds; with NUM_PORTS=2 that's still ~10 retries/sec/port across
        # the spray window, well above the per-port success rate needed for
        # simultaneous-open. Keep same_machine=True at the previous tight
        # cadence since loopback has no NAT mapping to keep alive.
        if not same_machine:
            time.sleep(0.05)


def sleep_until(punch_time: float, f_timer: Any, max_sleep: int = 10) -> None:
    """Block until punch_time (from f_timer()), sleeping at most max_sleep seconds."""
    now = f_timer()
    sleep_time = max(0, punch_time - now)

    # Cap sleep time to avoid large blocks if the host clock is far behind
    if sleep_time > max_sleep:
        sleep_time = max_sleep

    if sleep_time > 0:
        time.sleep(sleep_time)
