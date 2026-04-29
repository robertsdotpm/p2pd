"""Pure-sync UDP hole-punch engine.

UDP is connectionless, so the engine is simpler than tcp_punch:

  1. bind one DGRAM socket per (src_bind, dst_port) port_alloc
  2. wait until punch_time (NTP-synchronised barrier)
  3. spray PROBE frames from each bound socket to (peer_ext_ip,
     dst_port) for spray_duration seconds
  4. concurrently watch every bound socket via select() for inbound
  5. first valid PROBE inbound -> reply with CONFIRM on the same
     4-tuple; first valid CONFIRM inbound -> winner.

No process pool / no reverse-connect: UDP success is in-process so
the engine returns the winning socket directly. The caller wraps
that socket in a Pipe(UDP, dest, route, sock=existing).

Lessons re-applied from random_probe:
  * Pure blocking sockets + select(); never register on asyncio
    selectors during the algorithm phase. After ~256 add_reader/
    remove_reader cycles asyncio's selector silently stops firing
    _read_ready and the wrap goes deaf.
  * MSG_PEEK to look at unrecognised frames so application traffic
    arriving early on the bound port isn't drained by the punch
    loop -- the post-punch Pipe wrap needs that data.
"""
from typing import Any, Dict, List, Optional, Tuple
import select
import socket
import time

from aionetiface import fstr, log, sock_has_data
from aionetiface.net.address import resolve_dest_tup

from ..tcp_punch.tcp_punch_utils import bind_punch_sockets
from .udp_punch_defs import (
    UDP_PUNCH_FRAME_LEN,
    UDP_PUNCH_KIND_CONFIRM,
    UDP_PUNCH_KIND_PROBE,
    build_frame,
    parse_frame,
)


# Module-level fallbacks. Per-call params dicts override these.
SPRAY_DURATION = 5.0
LISTEN_DURATION = 6.0
RETRY_INTERVAL = 0.05
SPRAY_INTERVAL = 0.02


def fire_probes(
    bound_socks: List[Tuple[Any, Any]],
    dest_ip: str,
    nonce: bytes,
    spray_duration: float,
    spray_interval: float = SPRAY_INTERVAL,
    stop_reader: Optional[Any] = None,
) -> None:
    """Spray PROBE frames at the destination for spray_duration seconds.

    Each bound socket sends to (dest_ip, alloc.dest_port) so the
    cross-product covers every predicted (src_port, dst_port) tuple
    the NAT could have allocated. spray_interval throttles to avoid
    thundering-herd on the local NAT and the peer's NIC.

    stop_reader is the project-wide stop socket (TraversalPlugin's
    self.stop_reader / Node.stop_rw[0]). When node_stop fires,
    sock_has_data flips True and the spray loop bails on the next
    iteration so the executor thread exits before the asyncio loop
    closes, killing the 'Event loop is closed' callback noise at
    teardown.
    """
    frame = build_frame(UDP_PUNCH_KIND_PROBE, nonce)
    end = time.monotonic() + spray_duration
    # Resolve the v6-link-local 4-tuple ONCE per dest_port and reuse
    # it every spray round. getaddrinfo is synchronous + IP-literal
    # so it costs ~microseconds, but doing it inside the inner loop
    # would still be wasteful at spray rates.
    af = bound_socks[0][1].family if bound_socks else socket.AF_INET
    dest_tups = [
        resolve_dest_tup(af, dest_ip, a.dest_port, socket.SOCK_DGRAM)
        for a, _ in bound_socks
    ]
    log(fstr(
        "udp_punch.fire_probes: starting spray dest_ip={0} sockets={1} dest_tups={2} duration={3}s nonce={4}",
        (dest_ip, len(bound_socks), dest_tups, spray_duration, nonce.hex()),
    ))
    rounds = 0
    while time.monotonic() < end:
        if stop_reader is not None and sock_has_data(stop_reader):
            log("udp_punch.fire_probes: stop_reader signalled; aborting spray")
            return
        for (_, s), tup in zip(bound_socks, dest_tups):
            try:
                s.sendto(frame, tup)
            except OSError:
                # ICMP-unreachable on some NATs surfaces as ECONNREFUSED
                # the NEXT sendto. Ignore -- next round will retry.
                pass
        rounds += 1
        time.sleep(spray_interval)
    log(fstr(
        "udp_punch.fire_probes: spray ended after {0} rounds dest_ip={1}",
        (rounds, dest_ip),
    ))


def log_sock_addr(sock: Any) -> str:
    """Format a socket's bound address as host:port for logs (best-effort)."""
    try:
        addr = sock.getsockname()
        return "{0}:{1}".format(addr[0], addr[1])
    except OSError:
        return "<closed>"




def watch_for_winner(
    bound_socks: List[Tuple[Any, Any]],
    nonce: bytes,
    listen_duration: float,
    retry_interval: float = RETRY_INTERVAL,
    stop_reader: Optional[Any] = None,
) -> Optional[Tuple[Any, Tuple[str, int]]]:
    """Watch every bound socket for inbound; return (winner_sock, peer_addr) or None.

    Two-phase rendezvous:
      * If we receive a PROBE (kind=0x01) with matching nonce, reply
        with CONFIRM (0x02) on the same socket+peer_addr.  Don't
        return yet -- our peer also needs to see CONFIRM to lock.
      * If we receive a CONFIRM (kind=0x02) with matching nonce,
        the peer has acknowledged our PROBE -- this is our winner.
        Return immediately so the caller can wrap the socket.

    Non-frame datagrams are LEFT in the kernel queue (we use
    MSG_PEEK). Real application traffic arriving on a bound port
    before convergence ends up routed to the wrapping Pipe, not
    consumed here.
    """
    socks = [s for _, s in bound_socks]
    if not socks:
        log("udp_punch.watch_for_winner: no bound sockets; nothing to watch")
        return None

    confirm_frame = build_frame(UDP_PUNCH_KIND_CONFIRM, nonce)
    end = time.monotonic() + listen_duration
    log(fstr(
        "udp_punch.watch_for_winner: watching {0} sockets at {1} duration={2}s nonce={3}",
        (len(socks), [log_sock_addr(s) for s in socks], listen_duration, nonce.hex()),
    ))
    probes_seen = 0
    confirms_seen = 0
    foreign_seen = 0

    while time.monotonic() < end:
        if stop_reader is not None and sock_has_data(stop_reader):
            log("udp_punch.watch_for_winner: stop_reader signalled; aborting")
            return None
        timeout = min(retry_interval, end - time.monotonic())
        if timeout < 0:
            break
        try:
            ready, _, _ = select.select(socks, [], [], timeout)
        except (OSError, ValueError):
            break

        for s in ready:
            # MSG_PEEK: don't drain unrecognised data.
            try:
                buf, addr = s.recvfrom(UDP_PUNCH_FRAME_LEN, socket.MSG_PEEK)
            except OSError:
                continue

            kind, recv_nonce = parse_frame(buf)
            if kind is None or recv_nonce != nonce:
                # Not a punch frame; leave it for the Pipe layer.
                foreign_seen += 1
                continue

            # It IS a punch frame -- consume the bytes off the queue.
            try:
                s.recvfrom(UDP_PUNCH_FRAME_LEN)
            except OSError:
                continue

            if kind == UDP_PUNCH_KIND_PROBE:
                probes_seen += 1
                log(fstr(
                    "udp_punch.watch_for_winner: PROBE on {0} from {1} (probes={2}); replying CONFIRM",
                    (log_sock_addr(s), addr, probes_seen),
                ))
                # Peer's mapping reached us; tell them we saw it.
                try:
                    s.sendto(confirm_frame, addr)
                except OSError as exc:
                    log(fstr(
                        "udp_punch.watch_for_winner: CONFIRM sendto failed on {0} to {1}: {2!r}",
                        (log_sock_addr(s), addr, exc),
                    ))
                # Don't lock yet: peer might still be in spray phase
                # and not listening. Continue watching for their
                # CONFIRM (or another PROBE arrival -- we'll accept
                # the first PROBE as a winner if no CONFIRM lands
                # within listen_duration; see end-of-loop fallback).
                continue

            if kind == UDP_PUNCH_KIND_CONFIRM:
                confirms_seen += 1
                log(fstr(
                    "udp_punch.watch_for_winner: CONFIRM on {0} from {1} -- WINNER",
                    (log_sock_addr(s), addr),
                ))
                return (s, addr)

    log(fstr(
        "udp_punch.watch_for_winner: listen_duration ended -- probes={0} confirms={1} foreign={2}",
        (probes_seen, confirms_seen, foreign_seen),
    ))

    # Fallback: no CONFIRM arrived but we may have replied to a PROBE.
    # Walk sockets once more peeking for any pending CONFIRM that
    # arrived just as we exited the loop.
    try:
        ready, _, _ = select.select(socks, [], [], 0.0)
    except (OSError, ValueError):
        ready = []
    for s in ready:
        try:
            buf, addr = s.recvfrom(UDP_PUNCH_FRAME_LEN, socket.MSG_PEEK)
        except OSError:
            continue
        kind, recv_nonce = parse_frame(buf)
        if kind == UDP_PUNCH_KIND_CONFIRM and recv_nonce == nonce:
            try:
                s.recvfrom(UDP_PUNCH_FRAME_LEN)
            except OSError:
                pass
            return (s, addr)

    return None


def drain_punch_residue(sock: Any, nonce: bytes) -> int:
    """Synchronously drain queued PROBE/CONFIRM frames sitting in the kernel
    buffer for *sock* before it's wrapped in a Pipe.

    Same shape as random_probe.drain_probe_residue: peek at each
    pending datagram via MSG_PEEK; when the leading bytes match a
    punch frame with our session nonce, consume it; otherwise stop
    so non-frame application data passes through to the wrapping
    Pipe untouched.
    """
    sock.setblocking(False)
    drained = 0
    while True:
        try:
            buf, _ = sock.recvfrom(UDP_PUNCH_FRAME_LEN, socket.MSG_PEEK)
        except (BlockingIOError, OSError):
            break
        kind, recv_nonce = parse_frame(buf)
        if kind is None or recv_nonce != nonce:
            break
        try:
            sock.recvfrom(UDP_PUNCH_FRAME_LEN)
        except OSError:
            break
        drained += 1
    return drained


def udp_punch_engine(
    af: Any,
    nic_id: Optional[str],
    port_allocs: List[Any],
    src_ip: Optional[str],
    dest_ip: str,
    f_sleep_until: Any,
    nonce: bytes,
    same_machine: bool = False,
    params: Optional[Dict[str, Any]] = None,
    stop_reader: Optional[Any] = None,
    route: Optional[Any] = None,
) -> Optional[Tuple[Any, Tuple[str, int]]]:
    """Drive a full UDP punch: bind, barrier-sleep, fire, watch, return winner.

    Returns (sock, peer_addr) for the winning 4-tuple, or None.

    nonce: 16 random bytes both sides agreed on via PunchMsg. Required
           to distinguish a real punch arrival from random scanner
           traffic that happened to hit a predicted src_port.
    """
    if params is not None:
        spray_duration = params.get("connect_timeout", SPRAY_DURATION)
        listen_duration = params.get("monitor_timeout", LISTEN_DURATION)
        retry_interval = params.get("retry_interval", RETRY_INTERVAL)
    else:
        spray_duration = SPRAY_DURATION
        listen_duration = LISTEN_DURATION
        retry_interval = RETRY_INTERVAL

    bound_socks = bind_punch_sockets(
        af, nic_id, port_allocs, src_ip,
        sock_type=socket.SOCK_DGRAM, route=route,
    )
    log(fstr(
        "udp_punch_engine: af={0} src_ip={1} dest_ip={2} bound={3}/{4}",
        (af, src_ip, dest_ip, len(bound_socks), len(port_allocs)),
    ))
    if not bound_socks:
        log("udp_punch_engine: NO sockets bound; aborting")
        return None

    # Synchronised barrier: wait for the agreed punch_time so both
    # sides spray in the same window.
    f_sleep_until()

    fire_probes(
        bound_socks, dest_ip, nonce,
        spray_duration=spray_duration, stop_reader=stop_reader,
    )
    winner = watch_for_winner(
        bound_socks, nonce, listen_duration,
        retry_interval=retry_interval, stop_reader=stop_reader,
    )

    if winner is None:
        log("udp_punch_engine: no convergence; returning None")
        # No converge; close every socket so we don't leak FDs.
        for _, s in bound_socks:
            try:
                s.close()
            except OSError:
                pass
        return None

    winner_sock, peer_addr = winner
    log(fstr(
        "udp_punch_engine: WINNER local={0} peer={1}",
        (log_sock_addr(winner_sock), peer_addr),
    ))
    # Close all OTHER sockets; the caller only needs the winner.
    for _, s in bound_socks:
        if s is winner_sock:
            continue
        try:
            s.close()
        except OSError:
            pass

    return (winner_sock, peer_addr)
