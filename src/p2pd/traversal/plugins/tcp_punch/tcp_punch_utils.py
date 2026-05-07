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
from aionetiface.utility.cmd_tools import cmd as run_shell_cmd


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
        #
        # SKIP ON WINDOWS XP: pcap forensics on XP-as-listener cross-NAT
        # punches show XP RSTing the established simul-open connection
        # ~174ms after the final ACK -- with SO_LINGER {1,0}, every
        # internal close() on the socket would produce that exact RST
        # signature.  Disabling SO_LINGER on XP lets us tell whether
        # the tear-down is an XP-side application close (we'd see a FIN
        # instead) or a TCP-stack-level RST (we'd still see an RST).
        # Currently disabled on all Windows pending the diagnosis; the
        # TIME_WAIT cost is per-test, the simul-open RST is a punch
        # killer.
        if sock_type == socket.SOCK_STREAM and sys.platform != "win32":
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


def connect_on_tcp_sockets(
    same_machine: bool,
    bound_infos: List[Tuple[Any, Any]],
    dest_ip: str,
    spray_duration: float = 5.0,
) -> None:
    """
    Strict one-shot connect_ex per socket; return immediately to the engine.

    Why one connect_ex per socket is enough:

    "Spam many SYNs" punch designs typically refer to firing many
    PARALLEL sockets bound to different source ports concurrently --
    that's still what we do, via NUM_PORTS=4 (with two-bucket overlap
    = 4 deterministic boundary ports per fire on each peer).  TEMPORAL
    repetition of connect_ex on the same socket does NOT emit additional
    SYNs on any modern TCP stack: once a non-blocking connect kicks the
    socket into SYN_SENT, repeated connect_ex returns EALREADY (Linux)
    / WSAEALREADY (Windows) / EISCONN (after established) -- no new
    SYN is queued by the kernel.  The kernel's TCP retransmit timer
    (RFC 6298: 1s, 3s, 6s, 12s, ... typical) is what actually causes
    additional SYNs to go on the wire if the first one is lost; that's
    fully autonomous, not driven by user-space.

    So per-socket it's: one connect_ex → kernel emits SYN → kernel
    handles retransmits → simul-open completes (or doesn't).  The
    parallel SYNs across N sockets (each bound to a different
    deterministic source port) give the engine N independent chances
    at convergence per fire.  Internet packet loss (~0.1%) makes the
    probability of ALL N SYNs being lost vanishingly small for N=4.

    Why one-shot is also correct on XP specifically:

    XP's tcpip.sys does NOT cleanly separate the connect-phase from the
    established-phase under async reuse.  ANY second call into the
    connect path on the same socket -- even one returning "harmless"
    WSAEWOULDBLOCK / WSAEINVAL / WSAEISCONN -- re-touches the kernel's
    connect state machine and is hostile to its simul-open transition.
    Strict one-shot avoids the re-touch.  (Note: this does NOT prevent
    XP from RSTing its own simul-open connections ~174ms after the
    handshake completes -- that's a separate intrinsic tcpip.sys
    behavior we ruled out at the kernel level; see CLAUDE.md "Windows
    XP tcp_punch cross-NAT simul-open RST".  But strict one-shot is
    the right baseline whether or not XP also tears the connection
    down.)

    Why we return immediately instead of sleeping `spray_duration`:

    The previous design slept the full spray_duration here before
    letting the engine's monitor poll the selector.  That blocked the
    monitor from observing the ESTABLISHED transition until well after
    it happened -- on XP cross-NAT specifically, the brief ESTABLISHED
    window (~180ms wide before XP RSTs) had already closed by the
    time we started polling.  Returning immediately gives the monitor
    the full engine window to observe transitions for any platform.
    The kernel handles SYN retransmits regardless of whether we sit
    in this function.

    same_machine and spray_duration are kept in the signature for
    engine-call compatibility but are no longer functionally used --
    timing is now controlled by the engine's monitor phase.
    """
    # First (and ONLY) connect_ex per socket.  Use the bind alloc's
    # src_port for diagnostic logging instead of getsockname() -- on
    # XP getsockname() during the connect transition can have weird
    # internal side effects (lock contention, half-initialised socket
    # state exposure) so it is avoided in the hot path.
    _ = same_machine  # accepted for signature compat with engine call
    _ = spray_duration  # kept in signature; engine controls timing via monitor
    for p, s in bound_infos:
        try:
            err = s.connect_ex((dest_ip, p.dest_port))
            # Log any errno except the well-known "in progress" / OK codes.
            if err not in (0, 36, 115, 10035):
                log("[ENGINE-DBG] connect_ex({0}:{1}) from src_port={2} -> errno={3}".format(
                    dest_ip, p.dest_port, p.src_port, err,
                ))
        except OSError as exc:
            log("[ENGINE-DBG] connect_ex raised: " + repr(exc))

    # Return immediately so the engine's monitor loop starts polling
    # the selector right away.  XP's brief ESTABLISHED window after
    # simul-open is ~180ms wide (T+140ms simul-open complete, T+320ms
    # XP RSTs) -- if we sleep 5s here before letting monitor start,
    # the entire window has closed by the time we observe the socket.
    # The peer also fires at the same wall-clock punch_time, so we
    # don't need to "hold" the spray for the peer; the peer's SYN
    # crosses ours within one RTT and the kernel completes simul-open
    # without further user-space pokes.


def sleep_until(punch_time: float, f_timer: Any, max_sleep: int = 10) -> None:
    """Block until punch_time (from f_timer()), sleeping at most max_sleep seconds."""
    now = f_timer()
    sleep_time = max(0, punch_time - now)

    # Cap sleep time to avoid large blocks if the host clock is far behind
    if sleep_time > max_sleep:
        sleep_time = max_sleep

    if sleep_time > 0:
        time.sleep(sleep_time)
