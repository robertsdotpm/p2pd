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
"""

from typing import Any, Dict, List, Optional, Tuple
import selectors
import socket
import time
from .utils import *
from ...utility.punch_utils import *

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
                except OSError:
                    pass

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
                except OSError:
                    pass

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

    pre_connect_infos, sel = setup_engine(af, port_allocs, src_ip, nic_id)

    # Wait for synchronized punch time frame
    f_sleep_until()

    # Initiate simultaneous open
    connect_on_tcp_sockets(
        same_machine, pre_connect_infos, dest_ip, spray_duration=spray_duration
    )

    # Immediately monitor, no blind sleep
    successful = socket_event_monitor(
        sel, monitor_duration=monitor_duration, retry_interval=retry_interval
    )

    sock_list = list(successful)

    # Application-level validation should still be done after this
    sock = choose_winning_tcp_sock(dest_ip, sock_list, our_ip)

    return sock
