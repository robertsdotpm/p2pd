import sys
import socket
import platform
import ipaddress
from io import BytesIO
from ..errors import *
from ..utility.cmd_tools import *

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

# Enum taken from netifaces.
AF_LINK = 17

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
NIC_FAIL = 3
EXT_FAIL = 4
IP_PRIVATE = 3
IP_PUBLIC = 4
IP_APPEND = 5
IP_BIND_TUP = 6
NOT_WINDOWS = platform.system() != "Windows"
SUB_ALL = [None, None]

# Fine tune various network settings.
NET_CONF = {
    # Seconds to use for a DNS request before timeout exception.
    "dns_timeout": 2,

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

    # Enable closing sock on error.
    "do_close": False,

    # Whether to set SO_LINGER. None = off.
    # Non-none = linger value.
    "linger": None,

    # Retry N times on reply timeout.
    "send_retry": 2,

    # Ref to an event loop.
    "loop": None
}

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
