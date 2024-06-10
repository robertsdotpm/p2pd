import sys
import socket
import platform
import struct
import ipaddress
import random
import copy
import ssl
from io import BytesIO
from .errors import *
from .cmd_tools import *

"""
You're supposed to have unique [src ip, src port, dest ip, dest port] 'tuples' for every end point but you can easily bypass this with UDP. But if you end up with multiple 'sockets' bound to the same endpoint then the OS is not going to route packets correctly. It might make sense to detect this somehow if debug mode is on and show a warning if such actions are detected.

There is also the case where you open a second socket with
the same endpoint and fail to track the state of the first
(and properly close it) which will cause messages to be
routed to the first socket and / or second. It will be
very hard to detect. Sockets need to be properly cleaned
up to avoid this error state.
"""

# Address class has determined host input is a domain.
HOST_TYPE_DOMAIN = 0

# Address class has determine host input is an IP.
HOST_TYPE_IP = 1

# Used to signal preferences for an IP family when multiple
# options are available after resolving a domain.
# For IPs passed it serves as addition error checking.
AF_ANY = 1337

# Error value.
AF_NONE = 80085

# Avoid annoying socket... to access vars.
AF_INET = socket.AF_INET
AF_INET6 = socket.AF_INET6
TCP = STREAM = SOCK_STREAM = socket.SOCK_STREAM
UDP = DGRAM = SOCK_DGRAM = socket.SOCK_DGRAM
RUDP = 1234

# Interfaces are categorized as whether they're ethernet or wireless.
INTERFACE_UNKNOWN = 0
INTERFACE_ETHERNET = 1
INTERFACE_WIRELESS = 2

# Network stack couldn't be determined.
UNKNOWN_STACK = 0

# Stack only supports IPv4.
IP4 = V4 = V4_STACK = AF_INET

# Stack only supports IPv6.
IP6 = V6 = V6_STACK = AF_INET6

V6_LINK_LOCAL_MASK = "fe80" + (":0000" * 7)

# Stack supports both IPv4 and IPv6.
DUEL_STACK = AF_ANY

# Valid stack lists.
VALID_AFS = [IP4, IP6]
VALID_STACKS = [DUEL_STACK, IP4, IP6]

# Used as a timeout argument to recv.
# Non_blocking means it will return immediately even when it has no data.
NET_NON_BLOCKING = 0

# This means it will only return when a message is received.
# Not good if the code is in a processing loop.
NET_BLOCKING = None

# Keep around 1000 messages that haven't been processed.
# Packets are dropped after that point.
NET_MAX_MSG_NO = 1000

# Maximum amount in bytes all the messages can add up to.
NET_MAX_MSGS_SIZEOF = 2 * 1024 * 1024

# Netmasks that are for public addresses.
ZERO_NETMASK_IP4 = "0.0.0.0"
ZERO_NETMASK_IP6 = "0000:0000:0000:0000:0000:0000:0000:0000"
BLACK_HOLE_IPS = {
    IP4: "192.0.2.1",
    IP6: "0100:0000:0000:0000:0000:0000:0000:0001"
}

# A value meaning 'listen to' or 'subscribe to' all messages.
VALID_LOOPBACKS = ["127.0.0.1", "::1"]
VALID_ANY_ADDR = ["0.0.0.0", "::"]
ANY_ADDR = ["0.0.0.0", "ff02::1", "::/0", "255.255.255.255"]
LOOPBACK_BIND = 3
NODE_PORT = 10001

# Address object types.
IPA_TYPES = ipa_types = (ipaddress.IPv4Address, ipaddress.IPv6Address)

ANY_ADDR_LOOKUP = {
    IP4: "0.0.0.0",
    IP6: "::"
}

LOCALHOST_LOOKUP = {
    IP4: "127.0.0.1",
    IP6: "::1",
}

# Convert string proto values to enums.
PROTO_LOOKUP = {
    "TCP": TCP,
    "UDP": UDP,
    "RUDP": RUDP
}

DATAGRAM_TYPES = [
    asyncio.selector_events._SelectorDatagramTransport,
    asyncio.DatagramTransport
]
if sys.platform == "win32":
    if hasattr(asyncio.proactor_events, "_ProactorDatagramTransport"):
        DATAGRAM_TYPES.append(asyncio.proactor_events._ProactorDatagramTransport)

STREAM_TYPES = [asyncio.Transport]
if sys.platform == "win32":
    STREAM_TYPES.append(asyncio.proactor_events._ProactorSocketTransport)

DATAGRAM_TYPES = tuple(DATAGRAM_TYPES)
STREAM_TYPES = tuple(STREAM_TYPES)

V4_VALID_ANY = ["*", "0.0.0.0", ""]
V6_VALID_ANY = ["*", "::", "::/0", "", "0000:0000:0000:0000:0000:0000:0000:0000"]
V6_VALID_LOCALHOST = ["localhost", "::1"]
V4_VALID_LOCALHOST = ["localhost", "127.0.0.1"]
VALID_LOCALHOST = ["localhost", "::1", "127.0.0.1"]
NIC_BIND = 1
EXT_BIND = 2
IP_PRIVATE = 3
IP_PUBLIC = 4
IP_APPEND = 5
IP_BIND_TUP = 6
NOT_WINDOWS = platform.system() != "Windows"

# Fine tune various network settings.
NET_CONF = {
    # Wrap socket with SSL.
    "use_ssl": 0,

    # Timeout for SSL handshake.
    "ssl_handshake": 4,

    # Protocol family used for the socket.socket function.
    "sock_proto": 0,

    # N seconds before a registering recv timeout.
    "recv_timeout": 2,

    # Only applies to TCP.
    "con_timeout": 2,

    # No of messages to receive per subscription.
    "max_qsize": 0,

    # Require unique messages or not.
    "enable_msg_ids": 0,

    # Number of message IDs to keep around.
    "max_msg_ids": 1000,

    # Reuse address tuple for bind() socket call.
    "reuse_addr": False,

    # Setup socket as a broadcast socket.
    "broadcast": False,

    # Buf size for asyncio.StreamReader.
    "reader_limit": 2 ** 16,

    # Return the sock instead of the base proto.
    "sock_only": False,

    # Disable closing sock on error.
    "no_close": True,

    # Whether to set SO_LINGER. None = off.
    # Non-none = linger value.
    "linger": None,

    # Ref to an event loop.
    "loop": None
}

af_to_v = lambda af: 4 if af == IP4 else 6
v_to_af = lambda v: IP4 if v == 4 else IP6
af_to_cidr = max_cidr = lambda af: 32 if af == IP4 else 128

class FakeSocket():
    def __init__(self, response_bytes):
        self._file = BytesIO(response_bytes)

    def makefile(self, *args, **kwargs):
        return self._file

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
            "r": "(([0-9]+[.]?){4})+"
        },
        "Linux": {
            "ping": 'ping %s -b -w %d' % (
                # Surrounds with single quotes.
                nix_arg_escape(bcast_ip),
                timeout
            ),
            "r": "[(](([0-9]+[.]?){4})[)]"
        },
        "Darwin": {
            # Surrounds with double-quotes.
            "ping": 'ping %s -t %d' % (
                mac_arg_escape(bcast_ip),
                timeout
            ),
            "r": "[(](([0-9]+[.]?){4})[)]"
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

def ip6_patch_bind_ip(ip_obj, bind_ip, interface):
    # Add interface descriptor if it's link local.
    if ip_obj.is_private:
        if to_s(bind_ip[0:2]).lower() == "fe":
            # Interface specified by no on windows.
            if platform.system() == "Windows":
                bind_ip = "%s%%%d" % (
                    bind_ip,
                    interface.nic_no
                )
            else:
                # Other platforms just use the name
                bind_ip = "%s%%%s" % (
                    bind_ip,
                    interface.name
                )

    return bind_ip

# Convert compact bind rule list to named access.
class BindRule():
    def __init__(self, bind_rule):
        self.platform = bind_rule[0]
        self.af = bind_rule[1]
        self.type = bind_rule[2]
        self.hey = bind_rule[3]
        self.norm = bind_rule[4]
        self.change = bind_rule[5]

# Return a BindRule if it matches the requirements.
def match_bind_rule(ip, af, plat, bind_rule, rule_type):
    bind_rule = BindRule(bind_rule)

    # Skip rule types we're not processing.
    if bind_rule.type != rule_type:
        return

    # Skip address types that don't apply to us.
    if type(bind_rule.af) == list:
        if af not in bind_rule.af:
            return
    else:
        if af != bind_rule.af:
            return

    # Skip platform rules that don't match us.
    if bind_rule.platform not in ["*", plat]:
        return

    # Check hey for matches.
    if type(bind_rule.hey) == list:
        if ip not in bind_rule.hey:
            return
    if type(bind_rule.hey) == int:
        if bind_rule.hey == IP_PRIVATE:
            try:
                ipr = ip_f(ip)
                if not ipr.is_private:
                    return
            except:
                pass

    return bind_rule

"""
Returns the correct bind tuple given an af and listen IP.

Designed to support all kinds of common listen addresses
and interface-specific addresses across platforms.
Special attention has been paid to simplifying IPv6 support.

The knowledge within this function has come from testing
many different address types across operating systems
and uses a data-driven table of edge-cases over implementing
edge-case code directly. This greatly simplifies the
original code while improving maintainability.
"""
async def binder(af, ip="", port=0, nic_id=None, loop=None, plat=platform.system()):
    # Table of edge-cases for bind() across platforms and AFs.
    bind_magic = [
        # Bypasses the need for interface details for localhost binds.
        ["*", VALID_AFS, IP_APPEND, VALID_LOCALHOST, LOCALHOST_LOOKUP[af], ""],

        # No interface added to IP for V6 ANY.
        ["*", IP6, IP_APPEND, V6_VALID_ANY, "::", ""],

        # Make sure to normalize unusual bind all values for v4.
        ["*", IP4, IP_APPEND, V4_VALID_ANY, "0.0.0.0", ""],

        # Windows needs the nic no added to v6 private IPs.
        ["Windows", IP6, IP_APPEND, IP_PRIVATE, "", "nic_id"],

        # ... whereas other operating systems use the interface name.
        ["*", IP6, IP_APPEND, IP_PRIVATE, "", "nic_id"],

        # Windows v6 bind any doesn't need scope ID.
        ["Windows", IP6, IP_BIND_TUP, V6_VALID_ANY, None, [3, 0]],

        # Localhost V6 bind tups don't need the scope ID.
        ["*", IP6, IP_BIND_TUP, V6_VALID_LOCALHOST, None, [3, 0]],

        # Other private v6 bind tups need the scope id in Windows.
        ["Windows", IP6, IP_BIND_TUP, IP_PRIVATE, None, [3, "nic_id"]],
    ]

    # Process IP_APPEND bind rules.
    bind_tup = None
    for bind_rule in bind_magic:
        bind_rule = match_bind_rule(ip, af, plat, bind_rule, IP_APPEND)
        if not bind_rule:
            continue

        # Do norm rule.
        if bind_rule.norm == "":
            pass # Todo: norm IP.
        else:
            if bind_rule.norm is not None:
                ip = bind_rule.norm

        # Do logic specific to IP_APPEND.
        if bind_rule.change is not None:
            if bind_rule.change == "nic_id":
                ip += f"%{nic_id}"
            else:
                ip += bind_rule.change

        # Only one rule ran per type.
        break

    # Lookup correct bind tuples to use.
    loop = loop or asyncio.get_event_loop()
    try:
        addr_infos = await loop.getaddrinfo(ip, port)
    except:
        addr_infos = []

    if not len(addr_infos):
        raise Exception("Can't resolve IPv6 address for bind.")
    
    # Set initial bind tup.
    bind_tup = addr_infos[0][4]
        
    # Process IP_BIND_TUP if needed.
    for bind_rule in bind_magic:
        # Skip rule types we're not processing.
        bind_rule = match_bind_rule(ip, af, plat, bind_rule, IP_BIND_TUP)
        if not bind_rule:
            continue

        # Apply changes to the bind tuple.
        offset, val_str = bind_rule.change
        if val_str == "nic_id":
            val = nic_id
        else:
            val = val_str
        bind_tup = list(bind_tup)
        bind_tup[offset] = val
        bind_tup = tuple(bind_tup)
            
        # Only one rule ran per type.
        break

    return bind_tup

"""
Provides an interface that allows for bind() to be called
with its own parameters as a Route object method. Allows
the IP and port used to be accessed inside it as properties.
Otherwise defaults to using IP and port already set in class
which would only be the case if this method were used from a
Bind object and not a Route object. So a lot of hacks here.
But that's the API I wanted.
"""
def bind_closure(self):
    async def bind(port=None, ips=None):
        if self.resolved:
            return
        
        # Bind parameters.
        port = port or self.bind_port
        ips = ips or self.ips
        if ips is None:
            # Bind parent.
            if hasattr(self, "interface") and self.interface is not None:
                route = self.interface.route(self.af)
                ips = route.nic()
            else:
                # Being inherited from route.
                ips = self.nic()

        # Number or name - platform specific.
        if self.interface is not None:
            nic_id = self.interface.id
        else:
            nic_id = None

        # Get bind tuple for NIC bind.
        self._bind_tups = await binder(
            af=self.af, ip=ips, port=port, nic_id=nic_id
        )

        # Save state.
        self.bind_port = port
        self.resolved = True
        return self
        
    return bind

"""
Mostly this class will not be used directly by users.
It's code is also shitty for res. Routes have superseeded this.
"""
class Bind():
    def __init__(self, interface, af, port=0, ips=None, leave_none=0):
        #if IS_DEBUG:
        #assert("Interface" in str(type(interface)))

        self.ips = ips
        self.interface = interface
        self.af = af
        self.resolved = False
        self.bind_port = port

        # Will store a tuple that can be passed to bind.
        self._bind_tups = ()
        if not hasattr(self, "bind"):
            self.bind = bind_closure(self)

    def __await__(self):
        return self.bind().__await__()

    async def res(self):
        return await self.bind()

    async def start(self):
        await self.res()

    def bind_tup(self, port=None, flag=NIC_BIND):
        # Handle loopback support.
        if flag == LOOPBACK_BIND:
            if self.af == IP6:
                return ("::1", self.bind_port)
            else:
                return ("127.0.0.1", self.bind_port)

        # Spawn a new copy of the bind tup (if needed.)
        tup = self._bind_tups
        if port is not None:
            tup = copy.deepcopy(tup)
            tup[1] = port

        # IP may not be set if invalid type of IP passed to Bind
        # and then the wrong flag type was used with it.
        if tup[0] is None:
            e = "Bind ip is none. Possibly an invalid IP "
            e += "(private and not public or visa versa) "
            e += "was passed to Bind for IPv6 causing no "
            e += "IP for the right type to be set. "
            e += "Also possible there were no link locals."
            raise Exception(e)

        #log("> binding to tup = {}".format(tup))
        return tup

    def supported(self):
        return [self.af]

async def socket_factory(route, dest_addr=None, sock_type=TCP, conf=NET_CONF):
    # Check route is bound.
    if not route.resolved:
        raise Exception("You didn't bind the route!")

    # Check addresses were processed.
    if dest_addr is not None:
        if not dest_addr.resolved:
            raise Exception("net sock factory: dest addr not resolved")
        else:
            if not dest_addr.port:
                raise Exception("net: dest port is 0!")

            # If dest_addr was a domain it will be AF_ANY.
            # We need to specify a type for the socket though.
            if route.af not in dest_addr.supported():
                raise Exception("Route af not supported by dest addr")

    # Create socket.
    sock = socket.socket(route.af, sock_type, conf["sock_proto"])

    # Useful to cleanup server sockets right away.
    if conf["linger"] is not None:
        # Enable linger and set it to its value.
        linger = struct.pack('ii', 1, conf["linger"])
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)

    # Reuse port to avoid errors.
    if conf["reuse_addr"]:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except:
            #log("> sock fac: cant set reuse port")
            pass
            # Doesn't work on Windows.

    # Set broadcast option.
    if conf["broadcast"]:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # This may be set anyway by the async wrappers.
    sock.settimeout(0)

    # Bind to specific interface if set.
    # Assume Linux -- admin needed to bind on a certain interface.
    # If the interface is default for address type then no need to
    # specifically bind to it (which requires root.)
    try:
        if route.interface is not None:

            is_default = route.interface.is_default(route.af)
            if not is_default and NOT_WINDOWS:
                #log("> attemping to bind to non default iface")
                sock.setsockopt(socket.SOL_SOCKET, 25, to_b(route.interface.id))
                #log("> success: bound to non default iface")
    except Exception:
        log_exception()
        log("> couldnt bind to specific iface.")
        if sock is not None:
            sock.close()
        return None 


    # Default = use any IPv4 NIC.
    # For IPv4 -- bind address depends on destination type.
    bind_flag = NIC_BIND
    bind_tup = None
    if dest_addr is not None:
        # Get loopback working.
        if dest_addr.is_loopback:
            bind_flag = LOOPBACK_BIND

    """
        else:

            # Use global address on IPv6 global scopes.
            # Otherwise use link local or private NIC addresses.
            if dest_addr.is_public and dest_addr.chosen == IP6:
                bind_flag = EXT_BIND
    else:
        # The assumption is they want their server to be reachable.
        if route.af == IP6:
            bind_flag = EXT_BIND
    """

    try:
        sock.bind(bind_tup or route.bind_tup(flag=bind_flag))
        return sock
    except Exception:
        log(f"Could not bind to interface af = {route.af}")
        log(f"sock = {sock}")
        log(bind_tup or route.bind_tup(flag=bind_flag))
        log_exception()
        if sock is not None:
            sock.close()

async def get_high_port_socket(route, sock_type=TCP):
    # Minimal config to pass socket factory.
    conf = {
        "broadcast": False,
        "linger": None,
        "sock_proto": 0,
        "reuse_addr": True
    }

    # Get a new socket bound to a high order port.
    for i in range(0, 20):
        n = rand_rang(2000, MAX_PORT - 1000)
        await route.bind(n)
        try:
            s = await socket_factory(
                route,
                sock_type=sock_type,
                conf=conf
            )
        except:
            continue

        return s, n
    
    raise Exception("Could not bind high range port.")

async def proto_recv(pipe):
    n = 1 if pipe.stream.proto == TCP else 5
    for _ in range(0, n):
        try:
            return await pipe.recv()
        except:
            continue

async def proto_send(pipe, buf):
    n = 1 if pipe.stream.proto == TCP else 5
    for _ in range(0, n):
        try:
            await pipe.send(buf)
            await asyncio.sleep(0.1)
        except:
            continue