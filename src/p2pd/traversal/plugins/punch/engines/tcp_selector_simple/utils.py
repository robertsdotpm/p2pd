import socket
import time
import selectors
from ...punch_defs import *
from aionetiface.net.bind.bind_rules import binder_sync
from aionetiface.net.net_utils import ip_strip_if

"""
These magic sock options are required for TCP hole punching on
different operating systems.
"""
def sock_opt_voodoo(s):
    s.setblocking(False)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except Exception:
        pass # SO_REUSEPORT is not available on all systems

def bind_tcp_sockets(af, nic_id, port_allocs, src_ip=None):
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
        print(bind_tup)
        try:
            s.bind(bind_tup)
            bound_socks.append((p, s))
        except OSError as e:
            # print(f"Could not bind to port {p}: {e}")
            # Port colission so don't save.
            s.close()

    return bound_socks

def listen_on_tcp_sockets(bound_infos):
    listen_infos = []
    for bound_info in bound_infos:
        p, s = bound_info
        try:
            s.listen(1)
            listen_infos.append((p, s))
        except OSError:
            s.close()

    return listen_infos

def connect_on_tcp_sockets(sel, bound_infos, dest_ip):
    connect_infos = []
    for bound_info in bound_infos:  
        p, s = bound_info
        try:
            # Initiate non-blocking connect (the "punch")
            # TODO: ipv6?
            s.connect_ex((dest_ip, p.dest_port))
            connect_infos.append((p, s))
        except OSError as e:
            s.close()
            # print(f"Could not bind/connect outbound on port {port}: {e}")
            continue

    return connect_infos

def sleep_until(punch_time, f_timer, max_sleep=10):
    now = f_timer()
    sleep_time = max(0, punch_time - now)
    
    # Cap sleep time to avoid large blocks if the host clock is far behind
    if sleep_time > max_sleep:
        sleep_time = max_sleep
        
    if sleep_time > 0:
        time.sleep(sleep_time)

