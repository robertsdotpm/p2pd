from .net import *
from .ip_range import *

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

def get_mac_address(name, netifaces):
    return netifaces.ifaddresses(name)[netifaces.AF_LINK][0]["addr"]
    
# Note: Discards subnet for single addresses.
async def netiface_addr_to_ipr(af, info, interface, loop, skip_bind_test):
    # Some interfaces might not have valid information set.
    if "addr" not in info:
        return None
    if "netmask" not in info:
        return None
    
    nic_ipr = IPRange(info["addr"], info["netmask"])

    """
    Some operating systems incorrectly list the netmask for
    single IPs. This is a patch that discards the netmask if
    a host portion is detected. Ranges should have all zeros
    for the host portion.
    """
    if nic_ipr.i_host:
        nic_ipr = IPRange(info["addr"])

    """
    If a range is detected test that the range is valid by
    trying to bind on the first and last address.
    """
    if not skip_bind_test and not nic_ipr.i_host:
        invalid_subnet = False
        for host_index in [0, -1]:
            ip_obj = nic_ipr[host_index]
            bind_ip = str(ip_obj)
            if af == IP6:
                bind_ip = ip6_patch_bind_ip(ip_obj, bind_ip, interface)

            s = socket.socket(af, TCP)
            try:
                addr_infos = await loop.getaddrinfo(
                    bind_ip,
                    0
                )
                s.bind(addr_infos[0][4])
            except Exception:
                log_exception()
                log(f"af = {af}, bind_ip = {bind_ip}")
                log(f"{addr_infos[0][4]}")
                log(f"{s}")
                log(">get routes invalid subnet for {}".format(str(nic_ipr)))
                invalid_subnet = True
            finally:
                s.close()
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
                    continue
                    
                # Use this interface GW info as the default.
                gws["default"][af] = net_info
                break
                
    return gws

