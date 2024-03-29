import sys
import re
import platform
import multiprocessing
import socket
import pprint
from functools import lru_cache
from .errors import *
from .settings import *
from .route import *
from .nat import *
from .route_table import *
if sys.platform == "win32":
    from .win_netifaces import *
else:
    import netifaces as netifaces

def get_interface_af(netifaces, name):
    af_list = []
    for af in [IP4, IP6]:
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
        # Should be called from exception handler only.
        self._loop.call_exception_handler({
            'message': message,
            'exception': exc,
            'transport': self,
            'protocol': self._protocol,
        })
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
        what_exception()
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

    wlan_names = ["wlp", "wireless", "wlan", "wifi"]
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

# Used for specifying the interface for sending out packets on
# in TCP streams and UDP streams.
class Interface():
    def __init__(self, name=None, stack=DUEL_STACK, nat=None, netifaces=None):
        super().__init__()
        self.resolved = False
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
            if self.name not in self.netifaces.interfaces():
                log(f"interface name {self.name} not in {self.netifaces.interfaces()}")
                raise InterfaceNotFound
            self.type = get_interface_type(self.name)
            self.nic_no = 0
            if hasattr(self.netifaces, 'nic_no'):
                self.nic_no = self.netifaces.nic_no(self.name)
                self.id = self.nic_no
            else:
                self.id = self.name

    def to_dict(self):
        from .var_names import TXT
        return {
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

    async def do_start(self, rp=None, skip_resolve=False):
        # Load internal interface details.
        if Interface.get_netifaces() is None:
            self.netifaces = await init_p2pd()

        # Process interface name in right format.
        self.load_if_info()

        # Get routes for AF.
        log(f"Starting resolve with stack type = {self.stack}")
        if rp == None:
            af_list = self.supported(skip_resolve=True)
            tasks = []
            for af in af_list:
                log(f"Attempting to resolve {af}")
                async def helper(af):
                    try:
                        self.rp[af] = await Routes(
                            [self],
                            af,
                            self.netifaces,
                            skip_resolve
                        )
                    except NoGatewayForAF:
                        # Empty route pool.
                        self.rp[af] = RoutePool()
                        log(f"No route for gw {af}")
                
                tasks.append(
                    asyncio.wait_for(
                        async_wrap_errors(
                            helper(af)
                        ),
                        15
                    )
                )

            # Get all the routes concurrently.
            try:
                await asyncio.gather(*tasks)
            except asyncio.TimeoutError:
                raise Exception("Could not start iface in 15s.")
        else:
            self.rp = rp

        # Update stack type based on routable.
        self.stack = get_interface_stack(self.rp)
        assert(self.stack in VALID_STACKS)
        self.resolved = True

        # Set MAC address of Interface.
        self.mac = await get_mac_address(self.name, self.netifaces)
        if self.mac is None:
            raise Exception("mac none.")

        return self
    
    async def start_local(self, rp=None, skip_resolve=True):
        return await self.do_start(rp=rp, skip_resolve=skip_resolve)

    async def start(self, rp=None, skip_resolve=False):
        return await self.do_start(rp=rp, skip_resolve=skip_resolve)

    def __await__(self):
        return self.start().__await__()

    def set_nat(self, nat):
        assert(isinstance(nat, dict))
        assert(nat.keys() == nat_info().keys())
        self.nat = nat

    async def load_nat(self):
        # Try to avoid circular imports.
        from .base_stream import pipe_open
        from .stun_client import STUNClient, STUN_CONF
        from .nat_test import fast_nat_test
        
        # IPv6 only has no NAT!
        if IP4 not in self.supported():
            nat = nat_info(OPEN_INTERNET, EQUAL_DELTA)
        else:
            # STUN is used to get the delta type.
            af = IP4
            stun_client = STUNClient(
                self,
                af
            )

            # Get the NAT type.
            route = await self.route(af).bind()
            pipe = await pipe_open(UDP, route=route, conf=STUN_CONF)

            # Run delta test.
            nat_type, delta = await asyncio.wait_for(
                asyncio.gather(*[
                    async_wrap_errors(
                        fast_nat_test(pipe, STUND_SERVERS[af])
                    ),
                    async_wrap_errors(
                        delta_test(stun_client)
                    )
                ]),
                timeout=4
            )

            nat = nat_info(nat_type, delta)
            await pipe.close()

        # Load NAT type and delta info.
        # On a server should be open.
        self.set_nat(nat)
        return nat

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

        # Main route is last.
        if af in self.rp:
            if len(self.rp[af].routes):
                return copy.deepcopy(self.rp[af].routes[-1])

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
        log(f"is_default set = {ret}")
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

    # Use route table for these OS family to determine if interface
    # is useful or not.
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
        
        """
        The 'is_interface_if' function depends on using the 'route' binary.
        If it does not exist then the code will fail and return no results.
        In this case default to name-based filtering of netifaces.
        """
        if len(results):
            return results

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

async def load_interfaces(netifaces=None, load_nat=True):
    netifaces = netifaces or Interface.get_netifaces()
    if netifaces is None:
        netifaces = await init_p2pd()

    # Get list of good interfaces with ::/0 or 0.0.0.0 routes.
    ifs = await filter_trash_interfaces(netifaces)
    ifs = to_unique(ifs)
    if ifs == []:
        # Something must have gone wrong so just use regular netifaces.
        ifs = netifaces.interfaces()

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
            
# Stores a list of interfaces for the machine.
class Interfaces():
    def __init__(self, interfaces=[]):
        self.started = False
        self.by_name = {}
        self.by_af = {
            AF_INET: [],
            AF_INET6: []
        }

        # Interfaces are added once we know their stack type.
        # which is know after they are 'started' to tell
        # which address family is routable to the Internet.
        for interface in interfaces:
            self.add(interface)

        if len(interfaces):
            self.started = True

    def add(self, interface):
        duel_stack = 1 if interface.stack == DUEL_STACK else 0
        if interface.stack == AF_INET or duel_stack:
            self.by_af[AF_INET].append(interface)

        if interface.stack == AF_INET6 or duel_stack:
            self.by_af[AF_INET6].append(interface)

        self.by_name[interface.name] = interface
        return interface

    def get(self, af):
        return self.by_af[af][0]

    # Load default interfaces.
    async def start(self, do_start=1): # pragma: no cover
        tasks = []

        # Load default interfaces.
        netifaces = Interface.get_netifaces()
        if self.names == {}:
            gws = netifaces.gateways()["default"]
            interface_one = None
            name_index = {}
            for af in [netifaces.AF_INET, netifaces.AF_INET6]:
                if af in gws:
                    name = gws["default"][af][1]
                    if name not in name_index:
                        interface = Interface(name)
                        if do_start:
                            tasks.append(
                                interface.start()
                            )

                        self.names[name] = interface
                        name_index[name] = 1

        # Get WAN IPs for interfaces concurrently.
        if len(tasks):
            await asyncio.gather(*tasks)

        # Add interfaces to address family index.
        for name in self.names:
            interface = self.names[name]
            self.add(interface)

        self.started = True
        return self

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

