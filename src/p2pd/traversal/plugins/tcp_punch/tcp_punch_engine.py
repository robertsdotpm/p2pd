"""
- Closing the STUN socket sends FIN, which can cause some NATs to drop the mapping, so the STUN socket must stay open until punching is finished
- TCP punching requires both peers to send SYN at the same time - sending too early can trigger RST and kill the connection
- Time sync is difficult; NTP can be off by 1-50 ms, which matters
- If timeout is short: in pipe code can tear connections that actually succeeded
- OS scheduling is enough to effect timing
- ProcessPoolExecutor is used so punching happens in child processes, giving more accurate timing and isolating busy connection spam from main app
- Using multiprocessing directly is brittle and works poorly
- Threads do work; but different processes works best
- TCP punching works works badly with blocking sockets and event loops
- The best network code to use is non-blocking polling
- Testing the punchers need different NIC IPs for binding for LAN punch and different WANs for punching over the Internet
- Worst NAT should ideally initiate first so the better NAT can use its received mapping with fewer messages, though this optimization isn't implemented and may not justify added complexity
- Edge case: multiple punches may cause STUN connections from same local endpoint

- LAN-only NIC-bind tests on BSD (FreeBSD/OpenBSD/NetBSD) hit a timing
  artefact that does NOT manifest in real cross-NAT use:

    * Both peers wait until punch_time and then call connect_ex() to send
      a SYN.  On BSD a socket that receives RST during SYN_SENT is dead
      forever -- subsequent connect_ex() returns the cached ECONNREFUSED
      and emits no further SYN.
    * If the two peers' NTP-synced wake-ups are more than ~10ms apart,
      the faster side's SYN arrives at the slower side's port BEFORE
      that port is in SYN_SENT.  The slower side's kernel has only a
      bound socket (no LISTEN, by design here) so it RSTs.  That kills
      the faster side's socket, then the slower side's eventual SYN
      hits the dead port and gets RST'd in return.  Both fail.
    * Internet NTP RTT of 50-100ms means SysClock can only sync peers
      to ~+/-50ms.  Local LAN NTP (chrony at 10.0.1.204 in our test
      bench) brings RTT to <1ms and the LAN tests pass.  The --ntp
      flag on demo/__main__.py points the node at a chosen NTP server
      explicitly for this reason.
    * Cross-NAT (real-world) tests are immune: the NAT's port-mapping
      timing absorbs the wake-up jitter.  EXT pathway tests against
      p2pd.net pass even when LAN simultaneous-open tests of the same
      pair fail.  So this is a test-bench tightness issue, not a
      production bug -- but if you regress NIC-bind LAN BSD tests,
      check NTP sync first before chasing punch code.
"""

from typing import Any, Dict, List, Optional, Tuple
import selectors
import socket
import time
from aionetiface import log
from .tcp_punch_utils import bind_tcp_sockets, connect_on_tcp_sockets
from .punch_utils import choose_winning_tcp_sock

# Module-level fallback defaults (used when params is None).
# The per-call values from params dicts take precedence.
CONNECT_TIMEOUT = 5.0
RETRY_INTERVAL = 0.05


def setup_engine(af: Any, port_allocs: List[Any], src_ip: Optional[str], nic_id: Optional[str]) -> Tuple[List[Any], Any]:
    """Bind all sockets for the given port allocations and register them with a selector."""
    # TCP hole punching uses ONE socket per port.
    # No listen sockets. Each socket will perform active open only.
    pre_connect_infos = bind_tcp_sockets(af, nic_id, port_allocs, src_ip)

    sel = selectors.DefaultSelector()

    # Register all sockets before connect so we do not miss early SYN/SYN-ACK
    for _, s in pre_connect_infos:
        s.setblocking(False)
        sel.register(s, selectors.EVENT_WRITE | selectors.EVENT_READ)

    return (pre_connect_infos, sel)


def socket_event_monitor(
sel: Any,
    monitor_duration: float = CONNECT_TIMEOUT,
    retry_interval: float = RETRY_INTERVAL,
) -> Any:
    """
    Poll the selector for `monitor_duration` seconds and collect successfully
    connected sockets.

    monitor_duration: how long to watch for connection events (seconds).
    retry_interval:   selector poll timeout per iteration (seconds).
    """
    successful = set()

    start_time = time.monotonic()
    end = start_time + monitor_duration

    while time.monotonic() < end:
        events = sel.select(timeout=retry_interval)

        for key, mask in events:
            sock = key.fileobj

            # WRITE means connect() completion path
            if mask & selectors.EVENT_WRITE:
                try:
                    err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if err == 0:
                        # Confirms TCP state reached ESTABLISHED
                        sock.getpeername()
                        successful.add(sock)
                        sel.modify(sock, selectors.EVENT_READ)
                    else:
                        log("[ENGINE-DBG] WRITE SO_ERROR={0} on {1}".format(
                            err, sock.getsockname(),
                        ))
                except OSError as exc:
                    log("[ENGINE-DBG] WRITE getsockopt/getpeername failed: {0}".format(repr(exc)))

            # READ means either data or simultaneous-open completion traffic
            if mask & selectors.EVENT_READ:
                try:
                    # Non-consuming probe
                    data = sock.recv(1, socket.MSG_PEEK)
                    if data:
                        successful.add(sock)
                except BlockingIOError:
                    # No payload yet, but socket alive
                    successful.add(sock)
                except OSError as exc:
                    log("[ENGINE-DBG] READ recv failed: {0}".format(repr(exc)))

    return successful


def tcp_selector_punch_engine(
af: Any,
    nic_id: Optional[str],
    port_allocs: List[Any],
    src_ip: Optional[str],
    dest_ip: str,
    f_sleep_until: Any,
    our_ip: Optional[str],
    same_machine: bool,
    params: Optional[Dict[str, Any]] = None,
) -> Optional[Any]:
    """
    TCP hole-punch engine.

    params: optional punch parameter dict (DEFAULT_PUNCH_PARAMS or FAST_PUNCH_PARAMS).
            Controls the spray and monitor window durations.  Defaults to the
            module-level CONNECT_TIMEOUT / RETRY_INTERVAL constants when None.
    """

    # Resolve timing values from params (or fall back to module-level constants).
    if params is not None:
        spray_duration = params.get("connect_timeout", CONNECT_TIMEOUT)
        monitor_duration = params.get("monitor_timeout", CONNECT_TIMEOUT)
        retry_interval = params.get("retry_interval", RETRY_INTERVAL)
    else:
        spray_duration = CONNECT_TIMEOUT
        monitor_duration = CONNECT_TIMEOUT
        retry_interval = RETRY_INTERVAL

    log("[ENGINE] tcp_selector_punch_engine af={0} src_ip={1} dest_ip={2} "
        "ports={3} spray={4}s monitor={5}s same_machine={6}".format(
            af, src_ip, dest_ip, len(port_allocs),
            spray_duration, monitor_duration, same_machine,
        ))
    pre_connect_infos, sel = setup_engine(af, port_allocs, src_ip, nic_id)
    log("[ENGINE] setup_engine bound {0}/{1} sockets".format(
        len(pre_connect_infos), len(port_allocs),
    ))

    # Wait for synchronized punch time frame
    log("[ENGINE] entering sleep_until -> punch rendezvous")
    f_sleep_until()

    # Initiate simultaneous open
    log("[ENGINE] sleep_until done; spraying {0} connects for {1}s".format(
        len(pre_connect_infos), spray_duration,
    ))
    connect_on_tcp_sockets(
        same_machine, pre_connect_infos, dest_ip, spray_duration=spray_duration,
    )

    # Immediately monitor, no blind sleep
    successful = socket_event_monitor(
        sel, monitor_duration=monitor_duration, retry_interval=retry_interval
    )

    sock_list = list(successful)
    log("[ENGINE] monitor done; successful={0}/{1}".format(
        len(sock_list), len(pre_connect_infos),
    ))

    # Application-level validation should still be done after this
    sock = choose_winning_tcp_sock(dest_ip, sock_list, our_ip)
    log("[ENGINE] choose_winning_tcp_sock -> {0}".format(
        "selected" if sock else "no winner",
    ))

    return sock
