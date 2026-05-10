"""Utilities for the simple TCP selector punch engine."""
import socket
import struct
import sys
import time
from aionetiface import fstr, log, log_exception
from aionetiface.net.bind.bind_rules import binder_sync
from aionetiface.net.net_utils import ip_strip_if
from aionetiface.net.socket import apply_nic_pin_sockopts
from aionetiface.utility.cmd_tools import cmd as run_shell_cmd


async def log_time_wait_residue(src_ip):
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


def sock_opt_voodoo(s):
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
    af,
    nic_id,
    port_allocs,
    src_ip=None,
    sock_type=socket.SOCK_STREAM,
    route=None,
):
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
        bound = False
        for retry in range(4):
            try_port = p.src_port + retry
            if try_port > 65535:
                break
            try_tup = binder_sync(af, ip_strip_if(bind_ip), try_port, nic_id)
            try:
                s.bind(try_tup)
                bound_socks.append((p, s))
                bound = True
                if retry:
                    log(fstr(
                        "bind_punch_sockets: port collision on {0}; rebind to +{1} succeeded",
                        (bind_tup, retry),
                    ))
                break
            except OSError as exc:
                if retry == 3:
                    bind_failures.append((bind_tup, repr(exc)))
                    s.close()
                    bound = True
        if not bound:
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
    af,
    nic_id,
    port_allocs,
    src_ip=None,
    route=None,
):
    """Create and bind one TCP socket per port allocation, returning successful (alloc, socket) pairs."""
    return bind_punch_sockets(
        af, nic_id, port_allocs, src_ip,
        sock_type=socket.SOCK_STREAM, route=route,
    )


def listen_on_tcp_sockets(bound_infos):
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
    same_machine,
    bound_infos,
    dest_ip,
    spray_duration=5.0,
):
    """Spray SYN packets at the destination for `spray_duration` seconds.

    Loops over the bound sockets calling connect_ex on each.  Both peers
    need to be in SYN_SENT when the other's SYN arrives for simul-open
    to fire; repeated user-space pokes maximise the chance of overlap
    even when one side starts slightly later than the other.  Cross-LAN
    runs sleep 5ms between iterations to avoid busy-spin; same-machine
    iterates flat-out since the loopback path has no RTT slack.

    spray_duration: how long to keep spraying (seconds).
    """
    start = time.monotonic()
    end = start + spray_duration
    first_iter = True
    while time.monotonic() < end:
        for p, s in bound_infos:
            try:
                err = s.connect_ex((dest_ip, p.dest_port))
                if first_iter and err not in (0, 36, 115, 10035):
                    log("[ENGINE-DBG] connect_ex({0}:{1}) from src_port={2} -> errno={3}".format(
                        dest_ip, p.dest_port, p.src_port, err,
                    ))
            except OSError as exc:
                if first_iter:
                    log("[ENGINE-DBG] connect_ex raised: " + repr(exc))
        first_iter = False

        if not same_machine:
            time.sleep(0.005)


def sleep_until(punch_time, f_timer, max_sleep=10):
    """Block until punch_time (from f_timer()), sleeping at most max_sleep seconds."""
    now = f_timer()
    sleep_time = max(0, punch_time - now)

    # Cap sleep time to avoid large blocks if the host clock is far behind
    if sleep_time > max_sleep:
        sleep_time = max_sleep

    if sleep_time > 0:
        time.sleep(sleep_time)
