import sys
import socket
import platform
import struct
import ipaddress
import random
import copy
import ssl
from io import BytesIO
from ..errors import *
from ..utility.cmd_tools import *
from .net_defs import *

af_to_v = lambda af: 4 if af == IP4 else 6
v_to_af = lambda v: IP4 if v == 4 else IP6
af_to_cidr = max_cidr = lambda af: 32 if af == IP4 else 128
i_to_af = lambda x: IP4 if x == 2 else IP6

def af_from_ip_s(ip_s):
    ip_s = to_s(ip_s)
    ip_obj = ip_f(ip_s)
    return v_to_af(ip_obj.version)

def ip_str_to_int(ip_str):
    ip_obj = ipaddress.ip_address(ip_str)
    if ip_obj.version == 4:
        pack_ip = socket.inet_aton(ip_str)
        return struct.unpack("!L", pack_ip)[0]
    else:
        ip_str = str(ip_obj.exploded)
        hex_str = to_h(socket.inet_pton(
            AF_INET6, ip_str
        ))
        return to_i(hex_str)

def netmask_to_cidr(netmask):
    # Already a cidr.
    if "/" in netmask:
        return int(netmask.replace("/", ""))

    as_int = ip_str_to_int(netmask) 
    return bin(as_int).count("1")

def cidr_to_netmask(cidr, af):
    end = 32 if af == AF_INET else 128
    buf = "1" * cidr
    buf += "0" * (end - cidr)
    n = int(buf, 2)
    if af == AF_INET:
        return (str(ipaddress.IPv4Address(n)))
    else:
        return str(ipaddress.IPv6Address(n).exploded)

def toggle_host_bits(netmask, ip_str, toggle=0):
    ip_obj = ipaddress.ip_address(ip_str)
    if "/" in netmask:
        cidr = int(netmask.split("/")[-1])
    else:
        cidr = netmask_to_cidr(netmask)
    as_int = ip_str_to_int(ip_str)
    as_bin = bin(as_int)[2:]
    net_part = as_bin[:cidr]
    if not toggle:
        host_part = "0" * (len(as_bin) - len(net_part))
    else:
        host_part = "1" * (len(as_bin) - len(net_part))

    bin_result = net_part + host_part
    n_result = int(bin_result, 2)
    if ip_obj.version == 4:
        return str(ipaddress.IPv4Address(n_result))
    else:
        return str(ipaddress.IPv6Address(n_result).exploded)

def get_broadcast_ip(netmask, gw_ip):
    return toggle_host_bits(netmask, gw_ip, toggle=1)

"""
- Removes %interface name after an IPv6.
- Expands shortened / or abbreviated IPs to
their longest possible form.

Why? Because comparing IPs considers IPv6s
to be 'different' if they have different interfaces
attached / missing them.

Or if you compare the same compressed IPv6 to
its uncompressed form (textually) then it
will give a false negative.
"""
def ipv6_norm(ip_val):
    ip_obj = ipaddress.ip_address(ip_val)
    if ip_obj.version == 6:
        return str(ip_obj.exploded)

    return str(ip_obj)

def ip_strip_if(ip):
    if isinstance(ip, str):
        if "%" in ip:
            parts = ip.split("%")
            return parts[0]
    
    return ip

def ip_strip_cidr(ip):
    if isinstance(ip, str):
        if "/" in ip:
            ip = ip.split("/")[0]

    return ip

def ip_norm(ip):
    # Stip interface scope id.
    ip = ip_strip_if(ip)

    # Strip CIDR.
    ip = ip_strip_cidr(ip)

    # Convert IPv6 to exploded form
    # if it's IPv6.
    ip = ipv6_norm(ip)

    return ip

def mac_norm(mac):
    parts = re.split("[:.-]", mac)
    parts = [ part.zfill(2).lower() for part in parts ]
    return "".join(parts)

def client_tup_norm(client_tup):
    if client_tup is None:
        return None
    
    ip = ip_norm(client_tup[0])
    return (ip, client_tup[1])
    
def is_socket_closed(sock):
    try:
        # this will try to read bytes without blocking and also without removing them from buffer (peek only)
        data = sock.recv(16, socket.MSG_DONTWAIT | socket.MSG_PEEK)
        if len(data) == 0:
            return True
    except BlockingIOError:
        return False  # socket is open and reading from it would block
    except ConnectionResetError:
        return True  # socket was closed for some other reason
    except Exception as e:
        log("unexpected exception when checking if a socket is closed")
        return False
    return False


"""
If trying to reach a destination that uses a private address
and its a machine in the LA, then binding() a local socket
to the wrong interface address means being unable to reach
that destination host. The machines routing table knows
what interface to use to reach such an address and most
of the addressing info is supported in P2PD (subnet info
currently hasn't been added.) So for now -- this is a hack.

It means try to connect to that address and let the machine
decide on the right interface to use. Then the socket
bind IP is looked up and the interface that matches that
address is loaded directly for use with the software.
It's a work-around until I properly add in subnet fields.

This code will be used to make the p2p connect code more
robust -- so that it works to hosts in the LAN and to
services on interfaces on the same machine.
"""
def determine_if_path(af, dest):
    # Setup socket for connection.
    src_ip = None
    s = socket.socket(af, UDP)

    # We don't care about connection success.
    # But avoiding delays is important.
    s.settimeout(0)
    try:
        # Large port avoids perm errors.
        # Doesn't matter if it exists or not.
        s.connect((dest, 12345))

        # Get the interface bind address.
        src_ip = s.getsockname()[0]
    finally:
        s.close()

    return src_ip

def avoid_time_wait(pipe):
    try:
        sock = pipe.sock
        linger = struct.pack('ii', 1, 0)
        sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_LINGER,
            linger
        )
    except Exception:
        # Not guaranteed on windows.
        log_exception()

# Not used presently but may be useful in future.
async def safe_sock_connect(loop, sock, dest):
    try:
        await loop.sock_connect(sock, dest)
        return True
    except ConnectionRefusedError:
        log("Connection refused: " + str(dest))
        return False
    except OSError as e:
        # Handles e.g. ENETUNREACH, ETIMEDOUT, ECONNRESET
        log("Socket connect error to " + str(dest) + ":" + str(e))
        return False