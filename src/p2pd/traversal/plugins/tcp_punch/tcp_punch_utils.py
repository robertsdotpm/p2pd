"""Utilities for the simple TCP selector punch engine."""
from typing import Any, List, Optional, Tuple
import errno
import selectors
import socket
import struct
import sys
import time
from aionetiface import fstr, log, log_exception
from aionetiface.net.bind.bind_rules import binder_sync
from aionetiface.net.net_utils import ip_strip_if
from aionetiface.net.socket import apply_nic_pin_sockopts
from aionetiface.utility.cmd_tools import cmd as run_shell_cmd

# Errno values that mean "the kernel received RST during SYN_SENT and the
# socket is now permanently dead" -- different across POSIX and WinSock,
# so build the set from whichever names exist on this platform.
RST_ERRNOS = set()
for rst_name in ("ECONNREFUSED", "WSAECONNREFUSED"):
    rst_val = getattr(errno, rst_name, None)
    if rst_val is not None:
        RST_ERRNOS.add(rst_val)


async def log_time_wait_residue(src_ip: Optional[str]) -> None:
    """Run `netstat -an` and log TIME_WAIT entries whose local IP matches src_ip.

    Best-effort post-mortem after a punch attempt. SO_LINGER {1,0} on
    punch sockets should make this count 0; anything else means some
    code path is closing one of our 4-tuples without the linger sockopt
    or that another socket on the same NIC/port leaked residue.

    Uses aionetiface.utility.cmd_tools.cmd which wraps
    create_subprocess_shell and falls back to a blocking
    subprocess.run in a thread-pool executor on event loops that
    don't support subprocess (SelectorEventLoop on Windows). That
    way the diag works on every platform we run on.
    """
    if not src_ip:
        return
    try:
        text = await run_shell_cmd("netstat -an", timeout=10)
    except Exception as exc:  # pylint: disable=broad-except
        # Diag is best-effort. Never let it kill the punch finally.
        log("[POST-PUNCH-DIAG] netstat failed: " + repr(exc))
        return

    if not text:
        log("[POST-PUNCH-DIAG] netstat returned empty output")
        return
    matches = []
    for ln in text.splitlines():
        if "TIME_WAIT" not in ln:
            continue
        # netstat shows the local endpoint in the second whitespace
        # column on Windows and (after the proto column) on Linux.
        # Cheap substring filter: just look for our src_ip as ip:port.
        if (src_ip + ":") in ln or (src_ip + ".") in ln:
            matches.append(ln.strip())
    log("[POST-PUNCH-DIAG] TIME_WAIT entries for src_ip={0}: count={1}".format(
        src_ip, len(matches),
    ))
    for m in matches[:16]:
        log("[POST-PUNCH-DIAG]   " + m)

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
                # If we are on FreeBSD, this failure is likely fatal for TCP punching
                if sys.platform.startswith("freebsd"):
                    log("Warning: Failed to set SO_REUSEPORT on FreeBSD. Punching will likely fail.")
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


def recreate_tcp_punch_socket(
    af: Any,
    nic_id: Optional[str],
    port_alloc: Any,
    src_ip: Optional[str] = None,
    route: Optional[Any] = None,
) -> Any:
    """Re-bind one TCP punch socket to the same source port after RST killed the previous fd.

    Linux, BSD, macOS and Windows all transition the kernel socket to a
    permanent CLOSED state when RST arrives during SYN_SENT --
    connect_ex returns ECONNREFUSED (or WSAECONNREFUSED on Windows) once
    and every subsequent call returns the cached error with no new SYN
    on the wire.  When the peer's clock is even modestly behind ours
    (XP NTP residual is the worst offender) our first SYN can land on
    the peer's NAT before its outbound mapping exists, the router RSTs,
    and our spray socket is silently dead for the rest of the punch
    window even though the peer's eventual SYN does come back.

    Mitigation: close the dead fd and re-create + re-bind to the same
    src_port mid-spray.  The outbound NAT mapping for that src_port stays
    live as long as a fresh SYN goes out within the NAT's TCP open timer
    (tens of seconds, comfortably inside the 5 s spray).  SO_LINGER {1,0}
    on the dead fd's close (set by sock_opt_voodoo + struct below)
    sends RST instead of FIN so the local 4-tuple releases immediately
    and the fresh bind doesn't TIME_WAIT-collide with itself.
    """
    if src_ip:
        bind_ip = src_ip
    else:
        bind_ip = "0.0.0.0" if af == socket.AF_INET else "::"

    s = socket.socket(af, socket.SOCK_STREAM)
    sock_opt_voodoo(s)
    apply_nic_pin_sockopts(s, route)
    try:
        s.setsockopt(
            socket.SOL_SOCKET, socket.SO_LINGER,
            struct.pack("ii", 1, 0),
        )
    except OSError:
        pass
    bind_tup = binder_sync(af, ip_strip_if(bind_ip), port_alloc.src_port, nic_id)
    s.bind(bind_tup)
    return s


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


def connect_on_tcp_sockets(
    same_machine: bool,
    bound_infos: List[Tuple[Any, Any]],
    dest_ip: str,
    spray_duration: float = 5.0,
    sel: Optional[Any] = None,
    af: Any = None,
    nic_id: Optional[str] = None,
    src_ip: Optional[str] = None,
    route: Optional[Any] = None,
) -> None:
    """
    Spray SYN packets at the destination for `spray_duration` seconds.

    spray_duration: how long to keep spraying (seconds).  The CLI default is
    5.0 s; FAST_PUNCH_PARAMS uses 2.0 s for LAN/protocol usage.

    Recreate-on-RST (all platforms): when a peer's SYN arrives at our NAT
    before our outbound mapping for that src_port exists, the router RSTs
    and the kernel kills our connecting socket -- subsequent connect_ex
    returns the cached ECONNREFUSED with no further SYN on the wire.  This
    is platform-universal (Linux/BSD/macOS/Windows all behave this way),
    not a BSD-only quirk; the relevant trigger in production is peer clock
    skew (XP NTP residual is the most common offender) firing the peer's
    SYN late enough that our SYN crosses an unmapped peer port.

    Pass sel + af + nic_id (+ src_ip / route as applicable) and any socket
    that returns an RST errno is closed, unregistered from the selector,
    re-bound to the same src_port via recreate_tcp_punch_socket, re-
    registered, and replaced in bound_infos in place.  The next spray
    iteration fires a fresh SYN from the same outbound NAT mapping so
    when the peer's eventual SYN comes in, it lands on a live socket.

    bound_infos is mutated in place; same_machine is forwarded only to
    decide whether to back off between spray iterations.
    """
    recreate_enabled = sel is not None and af is not None
    start = time.monotonic()
    end = start + spray_duration
    first_iter = True
    recreated = 0
    recreate_failures = 0
    while time.monotonic() < end:
        for i in range(len(bound_infos)):
            p, s = bound_infos[i]
            try:
                err = s.connect_ex((dest_ip, p.dest_port))
                if first_iter and err not in (0, 36, 115):
                    # 36=EINPROGRESS(BSD), 115=EINPROGRESS(Linux), 0=connected
                    # Anything else on first attempt is worth logging.
                    log("[ENGINE-DBG] connect_ex({0}:{1}) from {2} -> errno={3}".format(
                        dest_ip, p.dest_port, s.getsockname(), err,
                    ))
                if recreate_enabled and err in RST_ERRNOS:
                    try:
                        sel.unregister(s)
                    except (KeyError, ValueError, OSError):
                        pass
                    try:
                        s.close()
                    except OSError:
                        pass
                    try:
                        new_s = recreate_tcp_punch_socket(
                            af, nic_id, p, src_ip=src_ip, route=route,
                        )
                        sel.register(
                            new_s,
                            selectors.EVENT_WRITE | selectors.EVENT_READ,
                        )
                        bound_infos[i] = (p, new_s)
                        recreated += 1
                    except OSError as rebuild_exc:
                        recreate_failures += 1
                        log("[ENGINE-DBG] recreate after RST failed for src_port={0}: {1}".format(
                            p.src_port, repr(rebuild_exc),
                        ))
            except OSError as exc:
                if first_iter:
                    log("[ENGINE-DBG] connect_ex raised: {0}".format(repr(exc)))
        first_iter = False

        # Tight spray cadence -- both sides need to be in SYN_SENT when each
        # other's SYN arrives for simultaneous-open to work.  Without the
        # recreate-on-RST path above, a single early SYN-RST from the peer's
        # NAT (clock skew, slow wakeup) silently kills the spray; the small
        # sleep keeps the loop from busy-spinning while still maximising the
        # retry SYNs per second on platforms that allow it.
        if not same_machine:
            time.sleep(0.005)

    if recreated or recreate_failures:
        log("[ENGINE-DBG] connect_on_tcp_sockets recreated={0} failed={1} (RST mid-spray)".format(
            recreated, recreate_failures,
        ))


def sleep_until(punch_time: float, f_timer: Any, max_sleep: int = 10) -> None:
    """Block until punch_time (from f_timer()), sleeping at most max_sleep seconds."""
    now = f_timer()
    sleep_time = max(0, punch_time - now)

    # Cap sleep time to avoid large blocks if the host clock is far behind
    if sleep_time > max_sleep:
        sleep_time = max_sleep

    if sleep_time > 0:
        time.sleep(sleep_time)
