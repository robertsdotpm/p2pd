import sys
import re
import platform
import multiprocessing
import socket
import pprint
from functools import lru_cache
from .errors import *
from .settings import *
from .route_defs import *
from .route_utils import *
from .nat_utils import *
from .route_table import *
from .stun_client import *
from .nat_test import fast_nat_test
if sys.platform == "win32":
    from .win_netifaces import *
else:
    import netifaces as netifaces

def get_interface_af(netifaces, name):
    af_list = []
    for af in [IP4, IP6]:
        if af not in netifaces.ifaddresses(name):
            continue

        if len(netifaces.ifaddresses(name)[af]):
            af_list.append(af)

    if len(af_list) == 2:
        return DUEL_STACK
    
    if len(af_list) == 1:
        return af_list[0]
    
    return UNKNOWN_STACK

@lru_cache(maxsize=None)
def get_default_nic_ip(af):
    af = int(af)
    try:
        with socket.socket(af, socket.SOCK_DGRAM) as s:
            s.connect((BLACK_HOLE_IPS[af], 80))
            return s.getsockname()[0]
    except:
        log_exception()
        return ""

def get_default_iface(netifaces, afs=VALID_AFS, exp=1, duel_stack_test=True):
    for af in afs:
        af = int(af)
        nic_ip = get_default_nic_ip(af)
        for if_name in netifaces.interfaces():
            addr_infos = netifaces.ifaddresses(if_name)
            if af not in addr_infos:
                continue

            for addr_info in addr_infos[af]:
                if addr_info["addr"] == nic_ip:
                    return if_name
        
    return ""

async def init_p2pd():
    global ENABLE_UDP
    global ENABLE_STUN

    # Setup event loop.
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    loop.set_exception_handler(SelectorEventPolicy.exception_handler)
    
    def fatal_error(self, exc, message='Fatal error on transport'):
        er = {
            'message': message,
            'exception': exc,
            'transport': self,
            'protocol': self._protocol,
        }
        log(er)

        # Should be called from exception handler only.
        #self.call_exception_handler(er)
        self._force_close(exc)

    asyncio.selector_events._SelectorTransport._fatal_error = fatal_error

    # Attempt to get monkey patched netifaces.
    netifaces = Interface.get_netifaces()
    if netifaces is None:
        if sys.platform == "win32":
            """
            loop = get_running_loop()

            # This happens if the asyncio REPL is used.
            # Nested event loops are a work around.
            if loop is not None:
                import nest_asyncio
                nest_asyncio.apply()
            """
            netifaces = await Netifaces().start()
        else:
            netifaces = sys.modules["netifaces"]

        Interface.get_netifaces = lambda: netifaces

    # Are UDP sockets blocked?
    # Firewalls like iptables on freehosts can do this.
    sock = None
    try:
        # Figure out what address family default interface supports.
        if_name = get_default_iface(netifaces)
        af = get_interface_af(netifaces, if_name)
        if af == AF_ANY: # Duel stack. Just use v4.
            af = IP4

        # Set destination based on address family.
        if af == IP4:
            dest = ('8.8.8.8', 60000)
        else:
            dest = ('2001:4860:4860::8888', 60000)

        # Build new UDP socket.
        sock = socket.socket(family=af, type=socket.SOCK_DGRAM)

        # Attempt to send small msg to dest.
        sock.sendto(b'testing UDP. disregard this sorry.', 0, dest)
    except Exception:
        """
        Maybe in the future I write code as a fail-safe but for
        now I don't have time. It's better to show a clear reason
        why the library won't work then to silently fail.
        """
        raise Exception("Error this library needs UDP support to work.")
    

        ENABLE_UDP = False
        ENABLE_STUN = False
        log("UDP sockets blocked! Disabling STUN.")
        log_exception()
    finally:
        if sock is not None:
            sock.close()

    return netifaces

def get_interface_type(name):
    name = name.lower()
    if re.match("en[0-9]+", name) != None:
        return INTERFACE_ETHERNET

    eth_names = ["eth", "eno", "ens", "enp", "enx", "ethernet"]
    for eth_name in eth_names:
        if eth_name in name:
            return INTERFACE_ETHERNET

    wlan_names = ["wlx", "wlp", "wireless", "wlan", "wifi"]
    for wlan_name in wlan_names:
        if wlan_name in name:
            return INTERFACE_WIRELESS

    if "wl" == name[0:2]:
        return INTERFACE_WIRELESS

    return INTERFACE_UNKNOWN

def get_interface_stack(rp):
    stacks = []
    for af in [IP4, IP6]:
        if af in rp:
            if len(rp[af].routes):
                stacks.append(af)

    if len(stacks) == 2:
        return DUEL_STACK

    if len(stacks):
        return stacks[0]

    return UNKNOWN_STACK

def clean_if_list(ifs):
    # Otherwise use the interface type function.
    # Looks at common patterns for interface names (not accurate.)
    clean_ifs = []
    for if_name in ifs:
        if_type = get_interface_type(if_name)
        if if_type != INTERFACE_UNKNOWN:
            clean_ifs.append(if_name)

    return clean_ifs

# Used for specifying the interface for sending out packets on
# in TCP streams and UDP streams.
class Interface():
    def __init__(self, name=None, stack=DUEL_STACK, nat=None, netifaces=None):
        super().__init__()
        self.__name__ = "Interface"
        self.resolved = False
        self.netiface_index = None
        self.id = self.mac = self.nic_no = None
        self.nat = nat or nat_info()
        self.name = name
        self.rp = {IP4: RoutePool(), IP6: RoutePool()}
        self.v4_lan_ips = []
        self.guid = None
        self.netifaces = netifaces or Interface.get_netifaces()

        # Check NAT is valid if set.
        if nat is not None:
            assert(isinstance(nat, dict))
            assert(nat.keys() == nat_info().keys())

        # Can provide a stack type to skip processing unsupported AFs.
        # Otherwise all AFs are checked when start() is called.
        self.stack = stack
        assert(self.stack in VALID_STACKS)

    # Load mac, nic_no, and process name.
    def load_if_info(self):
        # Assume its an AF.
        if isinstance(self.name, int):
            if self.name not in [IP4, IP6, AF_ANY]:
                raise InterfaceInvalidAF

            self.name = get_default_iface(self.netifaces, afs=[self.name])

        # No name specified.
        # Get name of default interface.
        log(f"Load if info = {self.name}")
        if self.name is None or self.name == "":
            # Windows -- default interface name is a GUID.
            # This is ugly AF.
            iface_name = get_default_iface(self.netifaces)
            iface_af = get_interface_af(self.netifaces, iface_name)
            if iface_name is None:
                raise InterfaceNotFound
            else:
                self.name = iface_name

            # Allow blank interface names to be used for testing.
            log(f"> default interface loaded = {iface_name}")

            # May not be accurate.
            # Start() is the best way to set this.
            if self.stack == DUEL_STACK:
                self.stack = iface_af
                log(f"if load changing stack to {self.stack}")

        # Windows NIC descriptions are used for the name
        # if the interfaces are detected as all hex.
        # It's more user friendly.
        self.name = to_s(self.name)

        # Check ID exists.
        if self.netifaces is not None:
            if_names = self.netifaces.interfaces()
            if self.name not in if_names:
                log(f"interface name {self.name} not in {if_names}")
                raise InterfaceNotFound
            self.type = get_interface_type(self.name)
            self.nic_no = 0
            if hasattr(self.netifaces, 'nic_no'):
                self.nic_no = self.netifaces.nic_no(self.name)
                self.id = self.nic_no
            else:
                self.id = self.name

            self.netiface_index = if_names.index(self.name)

        return self

    def load_if_info_fallback(self):
        # Just guess name.
        # Getting this wrong will only break IPv6 link-local binds.
        self.id = self.name = "eth0"
        self.netiface_index = 0
        self.type = INTERFACE_ETHERNET

        # Get IP of default route.
        ips = {
            # Google IPs. Nothing special.
            IP4: "142.250.70.206",
            IP6: "2404:6800:4015:803::200e",
        }

        # Build a table of default interface IPs based on con success.
        # Supported stack changes based on success.
        if_addrs = {}
        for af in VALID_AFS:
            try:
                s = socket.create_connection((ips[af], 80))
                if_addrs[s.family] = s.getsockname()[0][:]
                s.close()
            except:
                continue

        # Same API as netifaces.
        class NetifaceShim():
            def __init__(self, if_addrs):
                self.if_addrs = if_addrs

            def interfaces(self):
                return [self.name]

            def ifaddresses(self, name):
                ret = {
                    # MAC address (blanket)
                    netifaces.AF_LINK: [
                        {
                            'addr': '',
                            'broadcast': 'ff:ff:ff:ff:ff:ff'
                        }
                    ],
                }

                for af in self.if_addrs:
                    ret[af] = [
                        {
                            "addr": self.if_addrs[af],
                            "netmask": "0"
                        }
                    ]

                return ret
            
        self.netifaces = NetifaceShim(if_addrs)

        # Patch is default.
        self.is_default = lambda x, y: True

    def to_dict(self):
        from .var_names import TXT
        return {
            "netiface_index": self.netiface_index,
            "name": self.name,
            "nic_no": self.nic_no,
            "id": self.id,
            "mac": self.mac,
            "is_default": {
                int(IP4): self.is_default(IP4),
                int(IP6): self.is_default(IP6)
            },
            "nat": {
                "type": self.nat["type"],
                "nat_info": TXT["nat"][ self.nat["type"] ],
                "delta": self.nat["delta"],
                "delta_info": TXT["delta"][ self.nat["delta"]["type"] ]
            },
            "rp": {
                int(IP4): self.rp[IP4].to_dict(),
                int(IP6): self.rp[IP6].to_dict()
            }
        }

    @staticmethod
    def get_netifaces():
        return None

    @staticmethod
    def list():
        return Interface.get_netifaces().interfaces()

    @staticmethod
    def from_dict(d):
        i = Interface(d["name"])
        i.netiface_index = d["netiface_index"]
        i.nic_no = d["nic_no"]
        i.id = d["id"]
        i.mac = d["mac"]
        def is_default_wrapper(af, gws=None):
            return d["is_default"][af]
        i.is_default = is_default_wrapper

        # Set the interface route pool.
        i.rp = {
            IP4: RoutePool.from_dict(d["rp"][int(IP4)]),
            IP6: RoutePool.from_dict(d["rp"][int(IP6)])
        }

        # Set interface part of routes.
        for af in VALID_AFS:
            for route in i.rp[af].routes:
                route.interface = i

        # Set NAT details.
        i.nat = nat_info(d["nat"]["type"], d["nat"]["delta"])

        # Set stack type of the interface based on the route pool.
        i.stack = get_interface_stack(i.rp)

        # Indicate the interface is fully resolved.
        i.resolved = True

        # ... and return it.
        return i

    # Make this interface printable because it's useful.
    def __str__(self):
        return pprint.pformat(self.to_dict())

    # Show a representation of this object.
    def __repr__(self):
        return f"Interface.from_dict({str(self)})"

    # Pickle.
    def __getstate__(self):
        return self.to_dict()

    # Unpickle.
    def __setstate__(self, state):
        o = self.from_dict(state)
        self.__dict__ = o.__dict__

    async def do_start(self, netifaces=None, min_agree=3, max_agree=6, timeout=2):
        log(f"Starting resolve with stack type = {self.stack}")

        # Load internal interface details.
        if Interface.get_netifaces() is None:
            self.netifaces = await init_p2pd()

        # Process interface name in right format.
        try:
            self.load_if_info()
        except:
            log_exception()

            self.load_if_info_fallback()

        # This will be used for the routes call.
        # It's only purpose is to pass in a custom netifaces for tests.
        netifaces = netifaces or self.netifaces

        # Get routes for AF.
        tasks = []
        for af in VALID_AFS:
            log(f"Attempting to resolve {af}")

            # Initialize with blank RP.
            self.rp[af] = RoutePool()

            # Used to resolve nic addresses.
            stun_clients = await get_stun_clients(af, max_agree, self)

            # Is this default iface for this AF?
            try:
                if self.is_default(af):
                    enable_default = True
                else:
                    enable_default = False
            except:
                # If it's poorly supported allow default NIC behavior.
                log_exception()
                enable_default = True
            log(f"{self.name} {af} {enable_default}")

            tasks.append(
                async_wrap_errors(
                    get_routes_with_res(
                        af,
                        min_agree,
                        enable_default,
                        self,
                        stun_clients,
                        netifaces,
                        timeout=timeout,
                    )
                )
            )

        # Get all the routes concurrently.
        results = await asyncio.gather(*tasks)
        results = [r for r in results if r is not None]
        for af, routes, link_locals in results:
            self.rp[af] = RoutePool(routes, link_locals)

        # Update stack type based on routable.
        self.stack = get_interface_stack(self.rp)
        assert(self.stack in VALID_STACKS)
        self.resolved = True

        # Set MAC address of Interface.
        self.mac = await get_mac_address(self.name, self.netifaces)
        if self.mac is None:
            # Currently not used for anything important.
            # Might as well not crash if not needed.
            log("Could not load mac. Setting to blank.")
            self.mac = ""

        # If there's only 1 interface set is_default.   
        ifs = clean_if_list(self.netifaces.interfaces())
        if len(ifs) == 1:
            self.is_default = lambda af, gws=None: True
    
        return self

    async def start(self, netifaces=None, min_agree=3, max_agree=6, timeout=2):
        return await self.do_start(
            netifaces=netifaces,
            min_agree=min_agree,
            max_agree=max_agree,
            timeout=timeout,
        )

    def __await__(self):
        return self.start().__await__()

    def set_nat(self, nat):
        assert(isinstance(nat, dict))
        assert(nat.keys() == nat_info().keys())
        self.nat = nat
        return nat

    async def load_nat(self, nat_tests=5, delta_tests=12, timeout=4):
        # Try to avoid circular imports.
        from .pipe_utils import pipe_open
        
        # IPv6 only has no NAT!
        if IP4 not in self.supported():
            af = IP6
            nat = nat_info(OPEN_INTERNET, EQUAL_DELTA)
            return self.set_nat(nat)
        else:
            af = IP4

        # Copy random STUN servers to use.
        test_no = max(nat_tests, delta_tests)
        stun_clients = await get_stun_clients(
            af,
            test_no,
            self
        )

        # Pipe is used for NAT tests using multiplexing.
        # Same socket, different dests, TXID ordered.
        route = await self.route(af).bind()
        pipe = await pipe_open(UDP, route=route)

        # Run delta test.
        nat_type, delta = await asyncio.gather(*[
            # Fastest fit wins.
            async_wrap_errors(
                fast_nat_test(
                    pipe,
                    test_no=nat_tests,
                ),
                timeout=timeout
            ),

            # Concurrent -- 12 different hosts
            # Threshold of 5 for consensus.
            async_wrap_errors(
                delta_test(
                    stun_clients,
                    test_no=delta_tests,
                    threshold=int(delta_tests / 2) - 1
                ),
                timeout=timeout
            )
        ])

        # Cleanup NAT test pipe.
        if pipe is not None:
            await pipe.close()

        # Sanity check nat / delta details.
        if None in [nat_type, delta]:
            raise ErrorCantLoadNATInfo("Unable to load nat.")

        # Load NAT type and delta info.
        # On a server should be open.
        nat = nat_info(nat_type, delta)
        return self.set_nat(nat)

    def get_scope_id(self):
        assert(self.resolved)

        # Interface specified by no on windows.
        if platform.system() == "Windows":
            return self.nic_no
        else:
            # Other platforms just use the name
            return self.name

    def nic(self, af):
        # Sanity check.
        if self.resolved:
            assert(af in self.what_afs())
        if self.rp != {} and len(self.rp[af].routes):
            return self.route(af).nic()

    def route(self, af=None, bind_port=0):
        # Sanity check.
        if self.resolved:
            af = af or self.supported()[0]
            assert(af in self.what_afs())

        # Main route is first.
        if af in self.rp:
            if len(self.rp[af].routes):
                return copy.deepcopy(self.rp[af].routes[0])

        raise Exception(f"No route for {af} found.")

    async def route_test(self, af):
        # Return route with no external address info set.
        nic_ips = await get_nic_private_ips(self, af, self.netifaces)
        if not len(nic_ips):
            return None

        return Route(
            af=af,
            nic_ips=nic_ips,
            ext_ips=[IPRange(BLACK_HOLE_IPS[af])],
            interface=self
        )

    """
    Using a default list of gateways like this has a small
    performance advantage but the cost is if the interfaces list
    changes at run time like a wifi network disconnecting then
    the is_default function may give the incorrect result. There
    should be a way to detect loss of internet connection though.
    """
    def is_default(self, af, gws=None):
        def try_netiface_check(af, gws):
            af = af_to_netiface(af)
            gws = gws or netiface_gateways(self.netifaces, get_interface_type, preference=af)
            def_gws = gws["default"]
            if af not in def_gws:
                return False
            else:
                info = def_gws[af]
                if info[1] == self.name:
                    return True
                else:
                    return False
        def try_sock_trick(af):    
            if_name = get_default_iface(
                self.netifaces,
                afs=[af]
            )
            if if_name == "":
                return False
            
            return self.name == if_name
        
        ret = try_sock_trick(af) or try_netiface_check(af, gws)
        return ret
    
    def supported(self, skip_resolve=0):
        if not skip_resolve:
            assert(self.resolved)

        if self.stack == UNKNOWN_STACK:
            raise Exception("Unknown stack")

        if self.stack == DUEL_STACK:
            return [IP4, IP6]
        else:
            return [self.stack]

    def what_afs(self):
        assert(self.resolved)
        return self.supported()

"""
Given a list of interfaces returned from netifaces
or the win_netifaces module this code will filter the list
so that only interfaces that are used for the Internet remain.
Already done in win_netifaces. Uses route tables for Linux and Mac.
Other OS is based on the interface name (not that accurate.)
"""
async def filter_trash_interfaces(netifaces=None):
    netifaces = netifaces or Interface.get_netifaces()
    ifs = netifaces.interfaces()
    os_family = platform.system()

    # Interface list already well filtered by win_netifaces.py.
    if os_family == "Windows":
        return ifs

    # Use route table for these OS family.
    """
    if os_family in ["Linux", "Darwin"]:
        tasks = []
        for if_name in ifs:
            async def worker(if_name):
                r = await is_internet_if(if_name)
                if r:
                    return if_name
                else:
                    return None

            tasks.append(worker(if_name))

        results = await asyncio.gather(*tasks)
        results = strip_none(results)
        
        
        The 'is_interface_if' function depends on using the 'route' binary.
        If it does not exist then the code will fail and return no results.
        In this case default to name-based filtering of netifaces.
        
        if len(results):
            return results
    """

    # Otherwise use the interface type function.
    # Looks at common patterns for interface names (not accurate.)
    clean_ifs = []
    for if_name in ifs:
        if_type = get_interface_type(if_name)
        if if_type != INTERFACE_UNKNOWN:
            clean_ifs.append(if_name)

    return clean_ifs

def log_interface_rp(interface):
    for af in VALID_AFS:
        if not len(interface.rp[af].routes):
            continue

        route_s = str(interface.rp[af].routes)
        log(f"> AF {af} = {route_s}")
        log(f"> nic() = {interface.route(af).nic()}")
        log(f"> ext() = {interface.route(af).ext()}")

def get_ifs_by_af_intersect(if_list):
    largest = []
    af_used = None
    for af in VALID_AFS:
        hay = []
        for iface in if_list:
            if af in iface.supported():
                hay.append(iface)

        if len(hay) > len(largest):
            largest = hay
            af_used = af

    return [largest, af_used]

async def list_interfaces(netifaces=None):
    netifaces = netifaces or Interface.get_netifaces()
    if netifaces is None:
        netifaces = await init_p2pd()

    # Get list of good interfaces with ::/0 or 0.0.0.0 routes.
    ifs = await filter_trash_interfaces(netifaces)
    ifs = to_unique(ifs)
    if ifs == []:
        # Something must have gone wrong so just use regular netifaces.
        ifs = netifaces.interfaces()

    ifs = sorted(ifs)
    return ifs

    # Start all interfaces.
    if_list = []
    tasks = []
    for if_name in ifs:
        if_info = str(netifaces.ifaddresses(if_name))
        log(f"Attempt to start if name {if_name}")
        log(f"Net iface results for that if = {if_info}")
        async def worker(if_name):
            try:
                interface = await Interface(if_name, netifaces=netifaces).start()
                try:
                    if load_nat:
                        await interface.load_nat()
                except Exception:
                    log("Failed to load nat for interface.")
                    # Just use the default NAT info.

                if_list.append(interface)
            except Exception:
                log_exception()
                return

        tasks.append(
            # Assume timeout = non-routable.
            worker(if_name)
        )

    await asyncio.gather(*tasks)

    # Filter any interfaces that have no routes.
    # This will filter out loopback and other crap interfaces.
    good_ifs = []
    for interface in if_list:
        for af in VALID_AFS:
            if len(interface.rp[af].routes):
                good_ifs.append(interface)
                break

    # Log interfaces and routes.
    log("> Loaded interfaces.")
    for if_no, interface in enumerate(good_ifs):
        log(f"> Routes for interface {if_no}:")
        log_interface_rp(interface)

    return good_ifs

async def load_interfaces(if_names):
    nics = []
    for if_name in if_names:
        try:
            nic = await Interface(if_name)
            await nic.load_nat()
            nics.append(nic)
        except:
            log_exception()

    return nics

# Given a list of Interface objs.
# Convert to dict and return a list.
def if_list_to_dict(if_list):
    dict_list = []
    for interface in if_list:
        d = interface.to_dict()
        dict_list.append(d)

    return dict_list

# Given a list of Interface dicts.
# Convert them back to Interfaces and return a list.
def dict_to_if_list(dict_list):
    if_list = []
    for d in dict_list:
        interface = Interface.from_dict(d)
        if_list.append(interface)

    return if_list

def get_if_by_nic_ipr(nic_ipr, netifaces):
    for if_name in netifaces.interfaces():
        valid_afs = [netifaces.AF_INET, netifaces.AF_INET6]
        addr_infos = netifaces.ifaddresses(if_name)
        for af in valid_afs:
            if af not in addr_infos:
                continue

            for info in addr_infos[af]:
                cidr = af_to_cidr(
                    netiface_to_af(af, netifaces)
                )

                needle_ipr = IPRange(info["addr"], cidr=cidr)
                if needle_ipr == nic_ipr:
                    i = Interface(if_name)
                    i.netifaces = netifaces
                    i.load_if_info()
                    return i
            
"""
On a computer that has multiple network interfaces
the right interface needs to be selected depending
on the target destination. The easiest way to do
this is to try connect to the destination without
binding the socket beforehand and checking what
local IP is used for the bind address. The IP will
correspond to a certain network interface which
can be double-checked against what interface is
intended as the source for a connection.
"""
async def select_if_by_dest(af, src_index, dest_ip, interface, ifs=[]):
    """
    All valid interfaces for the software can reach
    internet -- use original interface if the dest_ip
    is a public address.
    """
    cidr = af_to_cidr(af)
    dest_ipr = IPRange(dest_ip, cidr=cidr)
    if dest_ipr.is_public:
        return interface, src_index
    
    # Simply connects a non-blocking socket to the dest_ip
    # and checks the local IP used to select an Interface.
    bind_ip = determine_if_path(af, dest_ip)
    bind_ipr = IPRange(bind_ip, cidr=cidr)
    bind_interface = get_if_by_nic_ipr(
        bind_ipr,
        interface.netifaces,
    )

    # Unable to find associated interface.
    if bind_interface is None:
        return interface, src_index

    # Auto-selected interface matches chosen interface.
    # Return the chosen interface with no changes.
    if bind_interface.name == interface.name:
        return interface, src_index
    
    # If already exists return it instead.
    for if_index, needle_if in enumerate(ifs):
        if needle_if.name == bind_interface.name:
            return needle_if, if_index

    return interface, src_index

    # No longer load an IF if its not in their ifs set.
    return await bind_interface
        
    """
    If the interface that was auto-chosen by the OS
    was different to the one that the caller
    chose then the correct interface is returned.

    Not default is set to force manually choosing
    the interface for sockets as we don't want to
    load all addressing info just to determine
    if its a default interface for the address family.
    """    
    bind_interface.is_default = lambda x: False

    """
    Patches the partially loaded interface to have
    a route function that will return a route
    that binds to the correct bind IP. The
    external address is set from the other
    interfaces primary route.
    """
    route = interface.route(af)
    route = Route(af, [bind_ipr], route.ext_ips)
    route.interface = bind_interface
    def route_patch(af):
        return route
    
    bind_interface.route = route_patch
    return bind_interface

if __name__ == "__main__": # pragma: no cover
    async def test_interface():
        #out = await cmd("route print")
        out = await nt_route_print("Realtek Gaming 2.5GbE Family Controller")
        print(out)
        return

        i = Interface(AF_ANY)   
        await i.start()
        #af = i.stack if i.stack != DUEL_STACK else IP4
        #b = Bind(i, af)

        return
        if1 = await Interface("enp3s0").start()
        if2 = await Interface("wlp2s0").start()
        ifs = Interfaces([if1, if2])
        print(ifs.by_af)

    async_test(test_interface)

