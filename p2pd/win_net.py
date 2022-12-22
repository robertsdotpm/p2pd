# pragma: no cover
import re
from .utils import *
from .cmd_tools import *
from .net import *

async def nt_ipv6_routes(no): # pragma: no cover
    out = await cmd("route print")
    route_infos = re.findall("([0-9]+)\s+([0-9]+)\s+([^\s=]*)\s+([^\s=]*)[\r\n]+", out)
    ret = []
    if route_infos != None and len(route_infos):
        for route_info in route_infos:
            if_no, _, _, _ = route_info
            if int(if_no) == no:
                ret.append(route_info)

    return ret

async def nt_ipv6_find_cidr(no, gw_ip): # pragma: no cover
    route_infos = await nt_ipv6_routes(no)
    for route_info in route_infos:
        _, _, route_dest, route_gw = route_info
        if route_gw in gw_ip:
            if "::/0" not in route_dest:
                _, cidr_str = route_dest.split("::/")
                return int(cidr_str)

    return None

async def nt_ipconfig(desc=None, ipv4=None, ipv6=None): # pragma: no cover
    all_none = desc is None and ipv4 is None and ipv6 is None
    out = await cmd("ipconfig /all")
    out = out.split("\r\n\r\n")
    for nic_info in out:
        key_values = re.findall("\s+([^.]+)[\s.]+:([^\r\n]+[\r\n]+(\s{5,}[^\r\n]+)?)", nic_info)

        info = {}
        for key_value in key_values:
            key, value, _ = key_value
            key = key.strip()
            value = value.strip()
            if key == "Default Gateway":
                gw1 = value
                try:
                    if "\n" in value:
                        value = value.split("\n")
                        gw1, gw2 = value
                        gw1 = to_s(gw1.strip())
                        gw2 = to_s(gw2.strip())

                        ip_obj = ipaddress.ip_address(gw1)
                        if ip_obj.version == 4:
                            value = {
                                AF_INET: gw1,
                                AF_INET6: gw2
                            }
                            info[to_s(key)] = value
                            continue
                        else:
                            value = {
                                AF_INET: gw2,
                                AF_INET6: gw1
                            }
                            info[to_s(key)] = value
                            continue
                    else:
                        gw1 = to_s(gw1)
                        ip_obj = ipaddress.ip_address(gw1)
                        if ip_obj.version == 4:
                            value = {
                                AF_INET: gw1,
                            }
                            info[to_s(key)] = value
                            continue
                        else:
                            value = {
                                AF_INET6: gw1,
                            }
                            info[to_s(key)] = value
                            continue
                except:
                    # Likely no gateway.
                    continue

            info[to_s(key)] = to_s(value)

        if all_none:
            return info

        if desc:
            if "Description" in info:
                if info["Description"] == desc:
                    return info

        if ipv4:
            if "IPv4 Address" in info:
                if ipv4 in info["IPv4 Address"]:
                    return info

        if ipv6:
            if "IPv6 Address" in info:
                if ipv6 in info["IPv4 Address"]:
                    return info

    return None

"""
Desc is not passed to any command so
escaping here is not necessary.

Processes the 'interface' section
of the route print command on Windows.
Purpose is to extract the NIC no for
use in IPv6 scope_ids and MAC addr.
"""
async def nt_route_print(desc): # pragma: no cover
    out = await cmd('powershell "route print"')
    nic_infos = re.findall("([0-9]+)[.]+(?:([^.]*)\s)?[.]+([^\r\n]+)[\r\n]*", out)
    for nic_info in nic_infos:
        nic_no, nic_mac, nic_desc = nic_info
        if desc is None or desc in to_s(nic_desc):
            return {
                "no": int(nic_no),
                "mac": to_s(nic_mac),
                "name": to_s(nic_desc)
            }

    return None

