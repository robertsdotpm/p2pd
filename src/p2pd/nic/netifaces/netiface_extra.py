import re
from ...net.net_utils import *
from ...net.ip_range import *
from ...utility.cmd_tools import *
from ...net.bind.bind_rules import *

async def get_mac_mixed(if_name):
    mac_p = r"((?:[0-9a-fA-F]{2}[\s:-]*){6})"
    win_p = r"[0-9]+\s*[.]+([^.]+)\s*[.]+"
    grep_p = "egrep 'lladdr|ether|link'"
    win_f = lambda x: re.findall(win_p + re.escape(if_name), x)[0]
    vectors = {
        "Linux": [
            [
                fstr("cat /sys/class/net/{0}/address", (if_name,)),
                lambda x: x
            ],
            [
                fstr("ip addr show {0} | {1}", (if_name, grep_p,)),
                lambda x: re.findall(mac_p, x)[0]
            ]
        ],
        "OpenBSD": [
            [
                fstr("ifconfig {0} | {1}", (if_name, grep_p,)),
                lambda x: re.findall(r"\s+[a-zA-Z]+\s+([^\s]+)", x)[0]
            ]
        ],
        "Windows": [
            [
                "route print",
                win_f
            ]
        ]
    }
    vectors["Darwin"] = vectors["OpenBSD"]
    os_name = platform.system()
    if os_name not in vectors:
        return None
    
    try_vectors = vectors[os_name]
    for vector in try_vectors:
        lookup_cmd, proc_f = vector
        out = await cmd(lookup_cmd, er=None)
        try:
            out = proc_f(out).strip()
            out = out.replace(" ", "-")
            out = out.replace(":", "-")
            if not len(re.findall(mac_p, out)):
                continue

            return out
        except Exception:
            log_exception()
    
    if os_name not in ["Darwin", "Windows"]:
        try:
            import pyroute2
            with pyroute2.NDB() as ndb:
                with ndb.interfaces[if_name] as interface:
                    return interface["address"]
        except Exception:
            log_exception()
            return None

# Netifaces apparently doesn't use their own values...
def af_to_netiface(af):
    if af == IP4:
        return int(IP4)
        return netifaces.AF_INET
        
    if af == IP6:
        return int(IP6)
        return netifaces.AF_INET6

    return af

def netiface_to_af(af, netifaces):
    if af == netifaces.AF_INET:
        return IP4

    if af == netifaces.AF_INET6:
        return IP6

    return af

def is_af_routable(af, netifaces):
    af = af_to_netiface(af)
    return af in netifaces.gateways()

async def get_mac_address(name, netifaces):
    if not hasattr(netifaces.ifaddresses(name), "AF_LINK"):
        try:
            mac = await get_mac_mixed(name)
        except asyncio.CancelledError:
            raise
        except Exception:
            log_exception()
            return None

    mac = netifaces.ifaddresses(name)[netifaces.AF_LINK][0]["addr"]
    return mac_norm(mac)
    
# Note: Discards subnet for single addresses.
async def netiface_addr_to_ipr(af, nic_id, info):
    # Some interfaces might not have valid information set.
    if "addr" not in info:
        return None
    if "netmask" not in info:
        return None
    
    #info["addr"] = ip_strip_if
    log(
        fstr(
            "Netiface loaded nic ipr {0} {1} {2} {3}",
            (af, nic_id, info["addr"], info["netmask"],)
        )
    )
    nic_ipr = IPRange(info["addr"], cidr=max_cidr(af))

    """
    Some operating systems incorrectly list the netmask for
    single IPs. This is a patch that discards the netmask if
    a host portion is detected. Ranges should have all zeros
    for the host portion.
    """
    if nic_ipr.i_host:
        nic_ipr = IPRange(
            info["addr"],
            cidr=max_cidr(af),
        )

    """
    If a range is detected test that the range is valid by
    trying to bind on the first and last address.
    """
    if not nic_ipr.i_host:
        invalid_subnet = False
        for host_index in [0, -1]:
            ip_obj = nic_ipr[host_index]
            bind_ip = str(ip_obj)
            bind_tup = await binder_async(
                af,
                bind_ip,
                nic_id=nic_id
            )

            s = socket.socket(af, TCP)
            try:
                s.bind(bind_tup)
            except Exception:
                log_exception()
                log(fstr("af = {0}, bind_ip = {1}", (af, bind_ip,)))
                log(fstr("{0}", (bind_tup,)))
                log(fstr("{0}", (s,)))
                log(">get routes invalid subnet for {}".format(str(nic_ipr)))
            finally:
                s.close()
                #print("this s = ", s)
                break

        # Don't add this address to any route.
        if invalid_subnet:
            return None

    return nic_ipr

async def get_nic_private_ips(interface, af, netifaces, loop=None):
    loop = loop or asyncio.get_event_loop()
    nic_iprs = []
    if_name = interface.name
    if_addresses = netifaces.ifaddresses(if_name)
    if af not in if_addresses:
        return nic_iprs

    for info in if_addresses[af]:
        nic_ipr = await netiface_addr_to_ipr(af, info, interface, loop, skip_bind_test=0)
        if nic_ipr is None:
            continue

        if nic_ipr.is_public and af == IP6:
            continue

        nic_iprs.append(nic_ipr)

    return nic_iprs

"""
Netifaces doesn't return the right default interface
on android. Need a patch for this.
"""
def netiface_gateways(netifaces, get_interface_type, preference=AF_ANY):
    gws = netifaces.gateways()
    gateway = None
    iface = None
    
    # Netifaces may not always find the default gateway.
    # Use first interface that get_interface_type finds.
    if gws["default"] == {}:
        # Create a list of address families to check.
        if preference == AF_ANY:
            afs = VALID_AFS
        else:
            afs = [preference]
            
        # Check the address families of related GWs.
        for af in afs:
            # No entry for AF found in GW info.
            log(fstr("Trying {0} in netiface_gateways", (af,)))
            if af not in gws:
                continue
                
            # Check that there is info to check.
            if not len(gws[af]):
                continue
                
            # Check the interface name.
            for net_info in gws[af]:
                # Af already set.
                if af in gws["default"]:
                    continue
                
                # Try to determine interface type from name.
                if_name = net_info[1]
                if_type = get_interface_type(if_name)
                
                # Unknown / bad interface type.
                if if_type == INTERFACE_UNKNOWN:
                    log(fstr("iface type unknown {0}", (if_name,)))
                    continue
                    
                # Use this interface GW info as the default.
                if net_info[2]:
                    gws["default"][af] = net_info
                break
                
    return gws

