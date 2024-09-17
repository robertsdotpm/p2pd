from .utils import *
from .net import *

def ip6_patch_bind_ip(bind_ip, nic_id):
    # Add interface descriptor if it's link local.
    if to_s(bind_ip[0:2]).lower() in ["fe", "fd"]:
        # Interface specified by no on windows.
        if platform.system() == "Windows":
            bind_ip = "%s%%%d" % (
                bind_ip,
                nic_id
            )
        else:
            # Other platforms just use the name
            bind_ip = "%s%%%s" % (
                bind_ip,
                nic_id
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
        raise Exception(f"Can't resolve {ip} for bind.")
    
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
        self.__name__ = "Bind"
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

            # If dest_addr was a domain = AF_ANY.
            # Stills needs a sock type tho
            if route.af not in dest_addr.supported():
                raise Exception("Route af not supported by dest addr")

    # Create socket.
    sock = socket.socket(route.af, sock_type, conf["sock_proto"])

    # Useful to cleanup sockets right away.
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
            pass
            # Doesn't work on Windows.

    # Set broadcast option.
    if conf["broadcast"]:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # This may be set by the async wrappers.
    sock.settimeout(0)

    """
    Bind to specific interface if set.
    On linux root is sometimes needed to
    bind to a non-default interface.
    If the interface is default for
    address type then no need to
    specifically bind to it.
    """

    try:
        if route.interface is not None:
            # TODO: probably cache this.
            try:
                is_default = route.interface.is_default(route.af)
            except:
                log_exception()
                is_default = True

            if not is_default and NOT_WINDOWS:
                sock.setsockopt(socket.SOL_SOCKET, 25, to_b(route.interface.id))
    except Exception:
        log_exception()
        # Try continue -- an exception isn't always accurate.
        # E.g. Mac OS X doesn't support that sockopt but still works.

    # Default = use any IPv4 NIC.
    # For IPv4 -- bind address
    # depends on destination type.
    bind_flag = NIC_BIND
    if dest_addr is not None:
        # Get loopback working.
        if dest_addr.is_loopback:
            bind_flag = LOOPBACK_BIND

    # Choose bind tup to use.
    bind_tup = route.bind_tup(
        flag=bind_flag
    )

    # Attempt to bind to the tup.
    try:
        sock.bind(bind_tup)
        return sock
    except Exception:
        error = f"""
        Could not bind to interface
        af = {route.af}
        sock = {sock}"
        bind_tup = {bind_tup}
        """
        log(error)
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