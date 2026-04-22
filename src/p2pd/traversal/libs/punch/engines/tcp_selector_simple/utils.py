import socket
import time
from ...punch_defs import *
from aionetiface.net.bind.bind_rules import binder_sync
from aionetiface.net.net_utils import ip_strip_if

"""
These magic sock options are required for TCP hole punching on
different operating systems.
"""


def sock_opt_voodoo(s):
    # type: (Any) -> None
    s.setblocking(False)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except OSError:
        pass  # SO_REUSEPORT is not available on all systems

    """
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_SYNCNT, 2)
    except Exception:
        pass
    """


def bind_tcp_sockets(af, nic_id, port_allocs, src_ip=None):
    # type: (Any, Optional[str], List[Any], Optional[str]) -> List[Tuple[Any, Any]]
    # Listen address.
    if src_ip:
        bind_ip = src_ip
    else:
        bind_ip = "0.0.0.0" if af == socket.AF_INET else "::"

    # List of bound TCP sockets.
    bound_socks = []
    for p in port_allocs:
        s = socket.socket(af, socket.SOCK_STREAM)
        sock_opt_voodoo(s)
        bind_tup = binder_sync(af, ip_strip_if(bind_ip), p.src_port, nic_id)
        try:
            s.bind(bind_tup)
            bound_socks.append((p, s))
        except OSError:
            # print(f"Could not bind to port {p}: {e}")
            # Port colission so don't save.
            s.close()

    return bound_socks


def listen_on_tcp_sockets(bound_infos):
    # type: (List[Tuple[Any, Any]]) -> List[Tuple[Any, Any]]
    listen_infos = []
    for bound_info in bound_infos:
        p, s = bound_info
        try:
            s.listen(1)
            listen_infos.append((p, s))
        except OSError:
            s.close()

    return listen_infos


def connect_on_tcp_sockets(same_machine, bound_infos, dest_ip, spray_duration=5.0):
    # type: (bool, List[Tuple[Any, Any]], str, float) -> None
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


def sleep_until(punch_time, f_timer, max_sleep=10):
    # type: (float, Any, int) -> None
    now = f_timer()
    sleep_time = max(0, punch_time - now)

    # Cap sleep time to avoid large blocks if the host clock is far behind
    if sleep_time > max_sleep:
        sleep_time = max_sleep

    if sleep_time > 0:
        time.sleep(sleep_time)
