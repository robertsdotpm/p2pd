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

class FakeSocket():
    def __init__(self, response_bytes):
        self._file = BytesIO(response_bytes)

    def makefile(self, *args, **kwargs):
        return self._file
    
    def close(self):
        return
    
    def _close_conn(self):
        return
    
    def flush(self):
        return

def af_from_ip_s(ip_s):
    ip_s = to_s(ip_s)
    ip_obj = ip_f(ip_s)
    return v_to_af(ip_obj.version)

def generate_mac(uaa=False, multicast=False, oui=None, separator=':', byte_fmt='%02x'):
    def rand_by(n):
        return [random.randrange(256) for _ in range(n)]

    mac = rand_by(8)
    if oui:
        if type(oui) == str:
            oui = [int(chunk) for chunk in oui.split(separator)]
        mac = oui + rand_by(num=6-len(oui))
    else:
        if multicast:
            mac[0] |= 1 # set bit 0
        else:
            mac[0] &= ~1 # clear bit 0
        if uaa:
            mac[0] &= ~(1 << 1) # clear bit 1
        else:
            mac[0] |= 1 << 1 # set bit 1
    return separator.join(byte_fmt % b for b in mac)

def mac_to_b(mac_str):
    mac = mac_str.replace(":", "")
    mac = mac.strip()
    while len(mac) < 12 :
        mac = '0' + mac
    macb = b''
    for i in range(0, 12, 2) :
        m = int(mac[i:i + 2], 16)
        macb += struct.pack('!B', m)
    return macb

async def sock_close_all(sock_list):
    if sock_list is not None:
        # Make it iterable.
        if type(sock_list) != list:
            sock_list = [ sock_list ]

        # Close all socks.
        for sock in sock_list:
            if sock is not None:
                await sock.close()

    return []

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
Host IP just needs to be any valid host IP in
the given subnet that corrosponds to the netmask.
Then the host portion is manipulated and the
network past is left alone.

Netmask is an IP in the same format as host_IP
with all the bits from the left set to 1 to
mask the network portion. Both netmask and
host_ip can be v4 or v6.

N is the offset from the last valid IP in the range.
Want the last valid IP? Set it to 0. Or the 10th from
the last? Then set it to 9.
"""
def ip_from_last(n, netmask, host_ip):
    assert(n)
    min_ip_str = toggle_host_bits(netmask, host_ip, toggle=0)
    max_ip_str = toggle_host_bits(netmask, host_ip, toggle=1)
    ip_obj = ipaddress.ip_address(host_ip)
    if ip_obj.version == 4:
        min_ip_n = int(ipaddress.IPv4Address(min_ip_str)) + 1
        max_ip_n = int(ipaddress.IPv4Address(max_ip_str)) - 1
    else:
        min_ip_n = int(ipaddress.IPv6Address(min_ip_str)) + 1
        max_ip_n = int(ipaddress.IPv6Address(max_ip_str)) - 1

    ip_n = -n % (max_ip_n + 1)
    if ip_n <= min_ip_n:
        ip_n = (-(min_ip_n - (n or min_ip_n)) or -1) % max_ip_n

    if ip_obj.version == 4:
        return str(ipaddress.IPv4Address(ip_n))
    else:
        return str(ipaddress.IPv6Address(ip_n).exploded)

def ipv6_rand_host(ip_val, cidr):
    # Back to an address.
    host_no = random.randrange(0, 2 ** cidr)
    int_val = int(ipaddress.IPv6Address(ip_val)) + host_no
    ip_str = str(ipaddress.IPv6Address(int_val))

    return ip_norm(ip_str)

def ipv6_rand_link_local():
    # Network portion for IPv6 link-local addresses
    # fe80:0000:0000:0000
    buf = "111111101" + ("0" * 55)

    # Blank host portion placeholder.
    buf += ("0" * 64)
    assert(len(buf) == 128)

    # Convert to IPv6 adddress.
    ip_obj = ipaddress.IPv6Address(int(buf, 2))
    ip_val = ipv6_norm(str(ip_obj))

    # Get result with a random host part.
    return ipv6_rand_host(ip_val, 64)

async def get_v4_lan_ips(bcast_ip, timeout=4): # pragma: no cover
    assert(type(timeout) == int)
    info_index = {
        "Windows": {
            "ping": 'ping %s -n %d' % (
                # Surrounds with double-quotes.
                win_arg_escape(bcast_ip), 
                int(timeout / 2) or 2
            ),
            "r": r"(([0-9]+[.]?){4})+"
        },
        "Linux": {
            "ping": 'ping %s -b -w %d' % (
                # Surrounds with single quotes.
                nix_arg_escape(bcast_ip),
                timeout
            ),
            "r": r"[(](([0-9]+[.]?){4})[)]"
        },
        "Darwin": {
            # Surrounds with double-quotes.
            "ping": 'ping %s -t %d' % (
                mac_arg_escape(bcast_ip),
                timeout
            ),
            "r": r"[(](([0-9]+[.]?){4})[)]"
        },
    }

    info = info_index[platform.system()]

    # Send ping command.
    out = await cmd(info["ping"], timeout=None)

    # Get arp results.
    out = await cmd("arp -a", timeout=None)

    # Get list of results.
    results = re.findall(info["r"], out)
    if results:
        return [result[0] for result in results]
    else:
        return []

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

async def proto_recv(pipe):
    n = 1 if pipe.sock.type == TCP else 5
    for _ in range(0, n):
        try:
            return await pipe.recv()
        except:
            continue

async def proto_send(pipe, buf):
    n = 1 if pipe.sock.type == TCP else 5
    for _ in range(0, n):
        try:
            await pipe.send(buf)
            await asyncio.sleep(0.1)
        except:
            continue

async def send_recv_loop(dest, pipe, buf, sub=SUB_ALL):
    #retry = 3
    n = 1 if pipe.sock.type == TCP else 3
    for _ in range(0, n):
        try:
            await pipe.send(buf, dest)
            return await pipe.recv(
                sub=sub,
                timeout=pipe.conf["recv_timeout"]
            )
        except asyncio.TimeoutError:
            log_exception()
            continue
        except Exception:
            log_exception()
        
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

