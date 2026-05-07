"""Utilities for the simple TCP selector punch engine."""
from typing import Any, List, Optional, Tuple
import random
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


def recreate_tcp_punch_socket(
    af: Any,
    nic_id: Optional[str],
    port_alloc: Any,
    src_ip: Optional[str] = None,
    route: Optional[Any] = None,
) -> Any:
    """Re-bind one TCP punch socket to the same source port.

    Used by the cycling spray (connect_on_tcp_sockets below) to refresh
    a socket mid-spray.  Old-school punchers found that XP's TCP stack
    gets stuck in inconsistent internal state if a single SYN_SENT
    socket is held for a long time; cycling close + recreate gives
    the kernel a fresh TCB each iteration, which sometimes catches
    the brief ESTABLISHED window that XP's stack tears down moments
    later.

    The same NAT outbound mapping is reused across the close because
    EQUAL_DELTA preservation means the NAT's mapping for src_port
    persists for the TCP open timer (tens of seconds) regardless of
    which socket on the LAN side is currently using it.
    """
    if src_ip:
        bind_ip = src_ip
    else:
        bind_ip = "0.0.0.0" if af == socket.AF_INET else "::"

    s = socket.socket(af, socket.SOCK_STREAM)
    sock_opt_voodoo(s)
    apply_nic_pin_sockopts(s, route)
    # Match bind_punch_sockets' SO_LINGER policy: skip on Windows so
    # cycling close() doesn't fire RSTs on still-in-progress sockets.
    if sys.platform != "win32":
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
    """Cycling spray: bind/connect/close/recreate per cycle, jittered intervals.

    Two-part fix for XP-as-listener simul-open instability:

    (A) Fresh sockets per cycle.  A persistent SYN_SENT socket on XP
    can sit in inconsistent kernel state for hundreds of ms after a
    crossing SYN arrives -- pcap shows simul-open completing on the
    wire, then XP unilaterally RSTing 174ms after the final ACK.
    Closing and recreating the socket on a short interval gives the
    kernel a fresh TCB; one of the cycles can catch the brief
    ESTABLISHED window before XP's stack tears it down.  Old-school
    punchers used this pattern (bind/connect/sleep/close/repeat)
    precisely for older Windows TCP quirks.

    (B) Jittered cycle interval.  Two peers running the same spray
    code on synchronised clocks would otherwise phase-lock their
    retransmit / cycle phases, every iteration potentially missing
    each other's ESTABLISHED window in the same way.  ±100ms uniform
    jitter per cycle desynchronises the peers' cycles so different
    relative offsets are exercised across the spray window.

    Note that this DOES require the bind metadata (sel/af/nic_id/
    src_ip/route) so we can recreate sockets and re-register them
    with the engine's selector; without those args we fall back to
    a one-shot connect_ex on the initial sockets.

    Same NAT mapping is reused across cycles -- EQUAL_DELTA NAT
    preservation holds the LAN_port -> WAN_port mapping for the TCP
    open timer (tens of seconds) regardless of which kernel socket
    on the LAN side is using it.

    Same-machine (LAN-back-to-self) usage skips cycling and uses a
    single connect_ex pass; the LAN path doesn't have the XP simul-
    open issue and the cycling overhead would slow LAN punches.

    spray_duration: total spray window (seconds). FAST_PUNCH_PARAMS
    uses 5.0s for tcp_punch.
    """
    cycling_enabled = (
        sel is not None and af is not None and not same_machine
    )

    if not cycling_enabled:
        # Fallback: one-shot connect_ex on the initial sockets and wait.
        for p, s in bound_infos:
            try:
                s.connect_ex((dest_ip, p.dest_port))
            except OSError as exc:
                log("[ENGINE-DBG] connect_ex raised: " + repr(exc))
        remaining = max(0.0, spray_duration - 0.005)
        if remaining > 0:
            time.sleep(remaining)
        return

    # Cycle interval: 200ms floor + 0..100ms jitter.  Yields ~3.5-5
    # cycles in a 1s window, ~17-25 cycles in a 5s spray.  Each cycle
    # is a complete close/recreate/connect, so each socket gets that
    # many independent SYN attempts -- one of them should overlap
    # with the peer's brief ESTABLISHED window if XP's stack is
    # transiently capable.
    cycle_floor = 0.20
    cycle_jitter_max = 0.10

    # Initial fire: connect on the freshly-bound sockets from setup_engine.
    initial_kicks = 0
    for p, s in bound_infos:
        try:
            s.connect_ex((dest_ip, p.dest_port))
            initial_kicks += 1
        except OSError as exc:
            log("[ENGINE-DBG] initial connect_ex raised: " + repr(exc))

    cycles = 0
    cycle_failures = 0
    end = time.monotonic() + spray_duration
    while True:
        # Jittered sleep -- random.uniform draws from a Mersenne Twister
        # seeded per process, so two peers running the same code don't
        # pick identical sequences.  Even if they did, the wall-clock
        # offset between their cycle starts would still drift.
        interval = cycle_floor + random.uniform(0, cycle_jitter_max)
        time.sleep(interval)
        if time.monotonic() >= end:
            break

        # Cycle: close + recreate + register + connect on every socket.
        for i in range(len(bound_infos)):
            p, old_s = bound_infos[i]
            # Drop the old socket (closes silently when SO_LINGER not
            # set -- on Windows we already skip SO_LINGER per the
            # bind_punch_sockets policy; on Linux SO_LINGER is set so
            # close fires RST, but a SYN_SENT socket without data has
            # no peer state to RST against in practice).
            try:
                sel.unregister(old_s)
            except (KeyError, ValueError, OSError):
                pass
            try:
                old_s.close()
            except OSError:
                pass
            # Fresh socket on same source port.  Kernel state cleared.
            try:
                new_s = recreate_tcp_punch_socket(
                    af, nic_id, p, src_ip=src_ip, route=route,
                )
            except OSError as rebuild_exc:
                cycle_failures += 1
                log("[ENGINE-DBG] cycle recreate failed for src_port={0}: {1}".format(
                    p.src_port, repr(rebuild_exc),
                ))
                continue
            try:
                sel.register(
                    new_s,
                    selectors.EVENT_WRITE | selectors.EVENT_READ,
                )
                bound_infos[i] = (p, new_s)
                new_s.connect_ex((dest_ip, p.dest_port))
                cycles += 1
            except OSError as exc:
                cycle_failures += 1
                log("[ENGINE-DBG] cycle connect_ex raised: " + repr(exc))

    log("[ENGINE-DBG] spray complete: initial_kicks={0} cycles={1} failures={2}".format(
        initial_kicks, cycles, cycle_failures,
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
