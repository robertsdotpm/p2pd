import sys
import re
import platform
import multiprocessing
from .errors import *
from .route import *
from .nat import *
from .route_table import *
if sys.platform == "win32":
    from .win_netifaces import *
else:
    import netifaces as netifaces

async def init_p2pd():
    netifaces = Interface.get_netifaces()
    if netifaces is not None:
        return netifaces
    
    multiprocessing.set_start_method("spawn")
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
    return netifaces

def get_default_iface(netifaces, preference=AF_ANY, exp=1, duel_stack_test=True):
    gws = netifaces.gateways()
    gateway = None
    iface = None

    # Convert any to netifaces.af.
    if preference == AF_ANY:
        # First valid address family for default gateway.
        preference = list(gws["default"])[0]
    else:
        preference = af_to_netiface(preference)
    
    # Get address of gateway for 'default' interface.
    preference = int(preference)
    if preference in gws["default"]:
        iface = gws["default"][preference][1]
            
    # Check found a default interface for ipv4 or ipv6.
    if iface == None:
        raise Exception("Couldn't find default WAN interface. Specify IPs manually in config to bypass this error.")

    # See if this iface is duel-stack.
    af = netiface_to_af(preference, netifaces)
    if duel_stack_test:
        af_index = VALID_AFS.index(preference)
        af_len = len(VALID_AFS)
        other_af = VALID_AFS[(af_index - 1) % af_len]
        try:
            other_iface, _ = get_default_iface(netifaces, other_af, duel_stack_test=False)
        except Exception:
            other_iface = None
        if other_iface == iface:
            af = DUEL_STACK
        
    return [iface, af]

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
        self.rp = {}
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

        # Assume its an AF.
        if isinstance(name, int):
            if name not in [IP4, IP6, AF_ANY]:
                raise InterfaceInvalidAF

            name, _ = get_default_iface(self.netifaces, preference=name)

        # No name specified.
        # Get name of default interface.
        if name is None or name == "":
            # Windows -- default interface name is a GUID.
            # This is ugly AF.
            iface_name, iface_af = get_default_iface(self.netifaces)
            if iface_name is None:
                raise InterfaceNotFound
            else:
                name = iface_name

            # Allow blank interface names to be used for testing.
            log("> default interface loaded")

            # May not be accurate.
            # Start() is the best way to set this.
            self.stack = iface_af

        # Windows NIC descriptions are used for the name
        # if the interfaces are detected as all hex.
        # It's more user friendly.
        self.name = to_s(name)

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

            # Set MAC address of Interface.
            self.mac = get_mac_address(self.name, self.netifaces)
            if self.mac is None:
                raise Exception("mac none.")

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
        return str(self.to_dict())

    # Show a representation of this object.
    def __repr__(self):
        return f"Interface.from_dict({self.to_dict()})"

    # Pickle.
    def __getstate__(self):
        return self.to_dict()

    # Unpickle.
    def __setstate__(self, state):
        o = self.from_dict(state)
        self.__dict__ = o.__dict__

    async def start_local(self, rp=None, skip_resolve=False):
        # Get routes for AF.
        if rp == None:
            af_list = VALID_AFS
            tasks = []
            for af in af_list:
                async def helper(af):
                    route = await self.route_test(af)
                    if route is None:
                        # Empty route pool.
                        self.rp[af] = RoutePool()
                    else:
                        self.rp[af] = RoutePool([route])

                tasks.append(helper(af))

            # Get all the routes concurrently.
            await asyncio.gather(*tasks)
        else:
            self.rp = rp

        # Update stack type based on routable.
        self.stack = get_interface_stack(self.rp)
        assert(self.stack in VALID_STACKS)
        self.resolved = True
        return self

    async def start(self, rp=None, skip_resolve=False):
        # Get routes for AF.
        if rp == None:
            af_list = VALID_AFS
            tasks = []
            for af in af_list:
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
                
                tasks.append(helper(af))

            # Get all the routes concurrently.
            await asyncio.gather(*tasks)
        else:
            self.rp = rp

        # Update stack type based on routable.
        self.stack = get_interface_stack(self.rp)
        assert(self.stack in VALID_STACKS)
        self.resolved = True
        return self

    def set_nat(self, nat):
        assert(isinstance(nat, dict))
        assert(nat.keys() == nat_info().keys())
        self.nat = nat

    async def load_nat(self):
        from .stun_client import STUNClient
        
        # Prefer IP4 if available.
        af = IP4
        if af not in self.supported():
            af = IP6

        # STUN is used to test the NAT.
        stun_client = STUNClient(
            self,
            af
        )

        # Load NAT type and delta info.
        # On a server should be open.
        nat = await stun_client.get_nat_info()
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

    def route(self, af=None):
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
        gws = gws or self.netifaces.gateways()
        af = af_to_netiface(af)
        def_gws = gws["default"]
        if af not in def_gws:
            return False
        else:
            info = def_gws[af]
            if info[1] == self.name:
                return True
            else:
                return False

    def supported(self):
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
        return strip_none(results)

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

async def load_interfaces(netifaces=None):
    # Get list of good interfaces with ::/0 or 0.0.0.0 routes.
    netifaces = netifaces or Interface.get_netifaces()
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
                await interface.load_nat()
                if_list.append(interface)
            except Exception:
                log_exception()
                return

        tasks.append(worker(if_name))

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

