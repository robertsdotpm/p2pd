from functools import lru_cache
from ..net.net import *
from ..net.ip_range import *
from .netiface_extra import *
from .nat.nat_utils import *
from .route.route_table import *
from ..protocol.stun.stun_client import *
from .route.route_defs import *

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
            name = s.getsockname()[0]
            s.close()
            return name
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

def get_interface_type(name):
    name = name.lower()
    if re.match(r"en[0-9]+", name) != None:
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

# Resolve the external addresses for an interface.
# Tries with public STUN servers first.
# Otherwise uses official p2pd servers.
async def route_res_with_fallback(af, is_default, nic, main_res):
    # Try the main 'decentralized' approach first.
    out = await async_wrap_errors(main_res)
    if out is not None:
        return out
    
def log_interface_rp(interface):
    for af in VALID_AFS:
        if not len(interface.rp[af].routes):
            continue

        route_s = str(interface.rp[af].routes)
        log(fstr("> AF {0} = {1}", (af, route_s,)))
        log(fstr("> nic() = {0}", (interface.route(af).nic(),)))
        log(fstr("> ext() = {0}", (interface.route(af).ext(),)))

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

def load_if_info_fallback(nic):
    # Just guess name.
    # Getting this wrong will only break IPv6 link-local binds.
    nic.id = nic.name = nic.name or "eth0"
    nic.netiface_index = 0
    nic.type = INTERFACE_ETHERNET

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
                # 17 = netifaces.AF_LINK enum.
                AF_LINK: [
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
        
    nic.netifaces = NetifaceShim(if_addrs)
    nic.is_default = nic.is_default_patch

def is_nic_default(nic, af, gws=None):
    def try_netiface_check(af, gws):
        af = af_to_netiface(af)
        if not gws:
            gws = netiface_gateways(
                nic.netifaces,
                get_interface_type,
                preference=af
            )

        def_gws = gws["default"]
        if af not in def_gws:
            return False
        else:
            info = def_gws[af]
            if info[1] == nic.name:
                return True
            else:
                return False
            
    def try_sock_trick(af):    
        if_name = get_default_iface(
            nic.netifaces,
            afs=[af]
        )
        if if_name == "":
            return False
        
        return nic.name == if_name
    
    try:
        ret = try_sock_trick(af) or try_netiface_check(af, gws)
        return ret
    except:
        log_exception()
        return False
    
# Load mac, nic_no, and process name.
def load_if_info(nic):
    # Assume its an AF.
    if isinstance(nic.name, int):
        if nic.name not in [IP4, IP6, AF_ANY]:
            raise InterfaceInvalidAF

        nic.name = get_default_iface(nic.netifaces, afs=[nic.name])

    # No name specified.
    # Get name of default interface.
    log(fstr("Load if info = {0}", (nic.name,)))
    if nic.name is None or nic.name == "":
        # Windows -- default interface name is a GUID.
        # This is ugly AF.
        iface_name = get_default_iface(nic.netifaces)
        iface_af = get_interface_af(nic.netifaces, iface_name)
        if iface_name is None:
            raise InterfaceNotFound
        else:
            nic.name = iface_name

        # Allow blank interface names to be used for testing.
        log(fstr("> default interface loaded = {0}", (iface_name,)))

        # May not be accurate.
        # Start() is the best way to set this.
        if nic.stack == DUEL_STACK:
            nic.stack = iface_af
            log(fstr("if load changing stack to {0}", (nic.stack,)))

    # Windows NIC descriptions are used for the name
    # if the interfaces are detected as all hex.
    # It's more user friendly.
    nic.name = to_s(nic.name)

    # Check ID exists.
    if nic.netifaces is not None:
        if_names = nic.netifaces.interfaces()
        if nic.name not in if_names:
            log(fstr("interface name {0} not in {1}", (nic.name, if_names,)))
            raise InterfaceNotFound
        nic.type = get_interface_type(nic.name)
        nic.nic_no = 0
        if hasattr(nic.netifaces, 'nic_no'):
            nic.nic_no = nic.netifaces.nic_no(nic.name)
            nic.id = nic.nic_no
        else:
            nic.id = nic.name

        nic.netiface_index = if_names.index(nic.name)

    return nic

def nic_from_dict(d, Interface):
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

def nic_to_dict(nic):
    from ..utility.var_names import TXT
    return {
        "netiface_index": nic.netiface_index,
        "name": nic.name,
        "nic_no": nic.nic_no,
        "id": nic.id,
        "mac": nic.mac,
        "is_default": {
            int(IP4): nic.is_default(IP4, None),
            int(IP6): nic.is_default(IP6, None)
        },
        "nat": {
            "type": nic.nat["type"],
            "nat_info": TXT["nat"][ nic.nat["type"] ],
            "delta": nic.nat["delta"],
            "delta_info": TXT["delta"][ nic.nat["delta"]["type"] ]
        },
        "rp": {
            int(IP4): nic.rp[IP4].to_dict(),
            int(IP6): nic.rp[IP6].to_dict()
        }
    }

# Given a list of Interface dicts.
# Convert them back to Interfaces and return a list.
def dict_to_if_list(dict_list, Interface):
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

async def load_interfaces(if_names, Interface):
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


