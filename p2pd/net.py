import sys
import socket
import platform
import struct
import ipaddress
import random
import copy
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
NIC_BIND = 1
EXT_BIND = 2
LOOPBACK_BIND = 3
NODE_PORT = 10001

# Address object types.
IPA_TYPES = ipa_types = (ipaddress.IPv4Address, ipaddress.IPv6Address)

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

IP_PRIVATE = 1
IP_PUBLIC = 2
NOT_WINDOWS = platform.system() != "Windows"

# Fine tune various network settings.
NET_CONF = {
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
    "no_close": False,

    # Whether to set SO_LINGER. None = off.
    # Non-none = linger value.
    "linger": None,

    # Ref to an event loop.
    "loop": None
}

v_to_af = lambda v: IP4 if v == 4 else IP6
max_cidr = lambda af: 32 if af == IP4 else 128

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
        loop = asyncio.get_event_loop()
        port = port or self.bind_port
        if ips is not None:
            # Tested.
            nic_bind, ext_bind = self._convert_ips(
                ips=ips,
                af=self.af,
                interface=self.interface,
            )
        else:
            # Being inherited by a Route object.
            if self.nic_bind is None and self.ext_bind is None:
                nic_bind = self.nic()
                ext_bind = self.ext()
            else:
                # Use interface fields set by _convert_ips.
                # Tested.
                nic_bind = self.nic_bind
                ext_bind = self.ext_bind

        # Creates two bind tuples for nic private IP and external address.
        for bind_info in [[NIC_BIND, nic_bind], [EXT_BIND, ext_bind]]:
            bind_type, bind_ip = bind_info
            if bind_ip is None:
                # Set a blank bind tuple for this.
                log("> bind type = {} was None".format(bind_type))
                self._bind_tups[bind_type] = (None, None)
                continue

            # Add scope ID for IPv6.
            if self.af == IP6:
                # Convert bind IP to an IPAddress obj.
                ip_obj = ip_f(bind_ip)

                # Add interface descriptor if it's link local.
                is_priv = ip_obj.is_private
                not_all = bind_ip != "::" # Needed for V6 AF_ANY for some reason.
                if is_priv and not_all:
                    # Interface specified by no on windows.
                    if platform.system() == "Windows":
                        bind_ip = "%s%%%d" % (
                            bind_ip,
                            self.interface.nic_no
                        )
                    else:
                        # Other platforms just use the name
                        bind_ip = "%s%%%s" % (
                            bind_ip,
                            self.interface.name
                        )

                # Get bind info using get address.
                # This includes the special 'flow info' and 'scope id'
                addr_infos = await loop.getaddrinfo(
                    bind_ip,
                    port
                )

                # (Host, port, flow info, interface ID)
                if not len(addr_infos):
                    raise Exception("Can't resolve IPv6 address for bind.")

                self._bind_tups[bind_type] = addr_infos[0][4]
            else:
                # Otherwise this is all you need.
                self._bind_tups[bind_type] = (bind_ip, port)

        #bind.addr = getattr(bind, 'addr', self._addr)
        self.nic_bind, self.ext_bind = nic_bind, ext_bind
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
        if leave_none:
            self.nic_bind = self.ext_bind = None
        else:
            self.nic_bind, self.ext_bind = self._convert_ips(
                ips=ips,
                af=af,
                interface=interface
            )

        # Will store a tuple that can be passed to bind.
        self._bind_tups = {NIC_BIND: None, EXT_BIND: None}
        self.bind = bind_closure(self)


    """
    ips param can be one of any number of types. The idea is to
    extract a target IP to bind on. This is a bit excessive but
    still. Here it is. 
    """
    def _convert_ips(self, ips, af, interface=None):
        # Use interface IPs.
        ip_val = ext_bind = nic_bind = None
        if interface is not None and ips is None:
            main_route = interface.route(af)
            nic_bind = main_route.nic()
            ext_bind = main_route.ext()

            # Make it so the program crashes if they
            # try to use a default ext when fetching
            # the bind tuple.
            if af == IP6 and not interface.resolved:
                ext_bind = None
                
            return nic_bind, ext_bind 

        # Only choose the version we need.
        if ips is not None and isinstance(ips, dict):
            ip_val = ips[af]

        # Code to pass an Interface or Address
        # to initalise the ips list.
        if isinstance(ips, str):
            ip_val = ips

        # No idea what ips is.
        if ip_val is None:
            raise NotImplemented("Can't bind to that type.")

        # Convert special values in IP val.
        if ip_val in ["", "*"]:
            if af == IP6:
                nic_bind = ext_bind = ip_val = "::"
            else:
                nic_bind = ext_bind = ip_val = "0.0.0.0"
        else:
            ip_val = ip_norm(ip_val)
            ip_obj = ip_f(ip_val)
            assert(af == v_to_af(ip_obj.version))
            nic_bind = ip_val
            ext_bind = ip_val

        return nic_bind, ext_bind

    async def res(self):
        return await self.bind()

    async def start(self):
        await self.res()

    def bind_ip(self, af=None):
        af = af or self.af
        return self.nic_bind if af == IP4 else self.ext_bind

    def bind_tup(self, port=None, flag=NIC_BIND):
        # Handle loopback support.
        if flag == LOOPBACK_BIND:
            if self.af == IP6:
                return ("::1", self.bind_port)
            else:
                return ("127.0.0.1", self.bind_port)

        # Spawn a new copy of the bind tup (if needed.)
        tup = self._bind_tups[flag]
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
        else:
            # Use global address on IPv6 global scopes.
            # Otherwise use link local or private NIC addresses.
            if dest_addr.is_public and dest_addr.chosen == IP6:
                bind_flag = EXT_BIND
    else:
        # The assumption is they want their server to be reachable.
        if route.af == IP6:
            bind_flag = EXT_BIND

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
