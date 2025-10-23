import sys
import re
import platform
import multiprocessing
import socket
import pprint
from functools import lru_cache
from ..errors import *
from ..settings import *
from .route.route_defs import *
from .route.route_utils import *
from .nat.nat_utils import *
from .route.route_table import *
from ..protocol.stun.stun_client import *
from .nat.nat_test import fast_nat_test
from .interface_utils import *
from ..entrypoint import *

# Used for specifying the interface for sending out packets on
# in TCP streams and UDP streams.
# Note: number of bad STUN servers means timeout should be higher.
# Maybe make this proportional to last server freshness age.
class Interface():
    def __init__(self, name=None, stack=DUEL_STACK, nat=None, netifaces=None, timeout=4):
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
        self.timeout = timeout

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
        log(fstr("Load if info = {0}", (self.name,)))
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
            log(fstr("> default interface loaded = {0}", (iface_name,)))

            # May not be accurate.
            # Start() is the best way to set this.
            if self.stack == DUEL_STACK:
                self.stack = iface_af
                log(fstr("if load changing stack to {0}", (self.stack,)))

        # Windows NIC descriptions are used for the name
        # if the interfaces are detected as all hex.
        # It's more user friendly.
        self.name = to_s(self.name)

        # Check ID exists.
        if self.netifaces is not None:
            if_names = self.netifaces.interfaces()
            if self.name not in if_names:
                log(fstr("interface name {0} not in {1}", (self.name, if_names,)))
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
        self.id = self.name = self.name or "eth0"
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
        self.is_default = self.is_default_patch

    def to_dict(self):
        from ..utility.var_names import TXT
        return {
            "netiface_index": self.netiface_index,
            "name": self.name,
            "nic_no": self.nic_no,
            "id": self.id,
            "mac": self.mac,
            "is_default": {
                int(IP4): self.is_default(IP4, None),
                int(IP6): self.is_default(IP6, None)
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


        i.is_default = lambda af, gws=None: d["is_default"][af]

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
        nic_info = str(self)

        return "Interface.from_dict(%s)" % (nic_info)

    # Pickle.
    def __getstate__(self):
        return self.to_dict()

    # Unpickle.
    def __setstate__(self, state):
        o = self.from_dict(state)
        self.__dict__ = o.__dict__

    async def do_start(self, netifaces=None, min_agree=2, max_agree=6, timeout=2):
        stack = self.stack
        log(fstr("Starting resolve with stack type = {0}", (stack,)))
        
        # Load internal interface details.
        self.netifaces = await init_p2pd()

        # Process interface name in right format.
        try:
            self.load_if_info()
        except InterfaceNotFound:
            raise InterfaceNotFound
        except:
            log_exception()
            self.load_if_info_fallback()

        # This will be used for the routes call.
        # It's only purpose is to pass in a custom netifaces for tests.
        netifaces = netifaces or self.netifaces

        # Get routes for AF.
        tasks = []
        for af in VALID_AFS:
            log(fstr("Attempting to resolve {0}", (af,)))

            # Initialize with blank RP.
            self.rp[af] = RoutePool()

            # Used to resolve nic addresses.
            servs = STUN_MAP_SERVERS[UDP][af]
            random.shuffle(servs[:max(20, max_agree)])
            stun_clients = await get_stun_clients(
                af,
                max_agree,
                self,
                servs=servs
            )
            assert(len(stun_clients) <= max_agree)


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
            log(fstr("{0} {1} {2}", (self.name, af, enable_default,)))

            # Use a threshold of pub servers for res.
            main_res = get_routes_with_res(
                af,
                min_agree,
                enable_default,
                self,
                stun_clients,
                netifaces,
                timeout=timeout,
            )

            # If it fails use 'official' servers.
            tasks.append(
                async_wrap_errors(
                    route_res_with_fallback(
                        af,
                        enable_default,
                        self,
                        main_res
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
            self.is_default = self.is_default_patch
    
        return self

    async def start(self, netifaces=None, min_agree=2, max_agree=6, timeout=2):
        return await self.do_start(
            netifaces=netifaces,
            min_agree=min_agree,
            max_agree=max_agree,
            timeout=timeout,
        )

    def __await__(self):
        return self.start(timeout=self.timeout).__await__()

    def set_nat(self, nat):
        assert(isinstance(nat, dict))
        assert(nat.keys() == nat_info().keys())
        self.nat = nat
        return nat
    
    async def do_load_nat(self, nat_tests=5, delta_tests=12, servs=None, timeout=4):
        # Try to avoid circular imports.
        from ..net.pipe.pipe_utils import pipe_open
        
        # IPv6 only has no NAT!
        if IP4 not in self.supported():
            af = IP6
            nat = nat_info(SYMMETRIC_NAT, RANDOM_DELTA)
            return self.set_nat(nat)
        else:
            af = IP4

        # Copy random STUN servers to use.
        test_no = max(nat_tests, delta_tests)
        stun_clients = await get_stun_clients(
            af,
            test_no,
            self,
            servs=servs
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
        
        return nat_type, delta

    async def load_nat(self, nat_tests=5, delta_tests=12, timeout=4):
        # Try main decentralized NAT test approach.
        nat_type, delta = await self.do_load_nat(
            nat_tests,
            delta_tests,
            timeout=timeout
        )
            
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

        raise Exception(fstr("No route for {0} found.", (af,)))

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
    
    def is_default_patch(self, af, gws=None):
        return True

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
        
        try:
            ret = try_sock_trick(af) or try_netiface_check(af, gws)
            return ret
        except:
            log_exception()
            return False
    
    def supported(self, skip_resolve=0):
        if not skip_resolve:
            assert(self.resolved)

        if self.stack == UNKNOWN_STACK:
            raise Exception("Unknown stack")

        if self.stack == DUEL_STACK:
            return sorted([IP4, IP6])
        else:
            return sorted([self.stack])

    def what_afs(self):
        assert(self.resolved)
        return self.supported()
    
# Given a list of Interface dicts.
# Convert them back to Interfaces and return a list.
def dict_to_if_list(dict_list):
    if_list = []
    for d in dict_list:
        interface = Interface.from_dict(d)
        if_list.append(interface)

    return if_list

# Given a list of Interface objs.
# Convert to dict and return a list.
def if_list_to_dict(if_list):
    dict_list = []
    for interface in if_list:
        d = interface.to_dict()
        dict_list.append(d)

    return dict_list

async def load_interfaces(if_names):
    """
When an interface is loaded, it is placed into a clearing queue.
The event loop cycles through this queue, switching between tasks as they
become eligible to run. Because completion time depends on how many other
interfaces are also pending, timeouts are set relative to the total number of
active interfaces rather than per task in isolation. This ensures that delays from
other tasks are accounted for and no single timeout is miscalculated by
assuming immediate execution.
    """
    nics = []
    if_len = len(if_names)
    for if_name in if_names:
        try:
            nic = await Interface(if_name)
            await nic.load_nat()
            nics.append(nic)
        except:
            log_exception()

    return nics
            
            
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

