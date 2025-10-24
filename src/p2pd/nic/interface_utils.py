from functools import lru_cache
from ..net.net import *
from ..net.ip_range import *
from .netiface_extra import *

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

