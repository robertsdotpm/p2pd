# pragma: no cover
import re
import winreg
from .utils import *
from .cmd_tools import *
from .net import *

"""
Net name is very specifically not the interface name or
its description. Examples of the net name are 'local area network.'
Examples of an interface name 'Intel ... ethernet v10'.

"""
def nt_get_net_infos():
    root_key = winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Control\Network",
        0,
        winreg.KEY_READ
    )

    # Recursively crawl all portions looking for the right field.
    # Windows loves to make things easy.
    def recurse_search(root_key, guid=None):
        results = []
        for sub_offset in range(0, winreg.QueryInfoKey(root_key)[0]):
            sub_name = winreg.EnumKey(root_key, sub_offset)
            sub_key = None
            try:
                sub_key = winreg.OpenKey(root_key, sub_name)
                if sub_name == "Connection":
                    con_name = winreg.QueryValueEx(sub_key, "Name")[0]
                    results.append([con_name, guid])
                else:
                    if re.match("{[^{}]+}", sub_name) == None:
                        continue

                    results += recurse_search(
                        sub_key,
                        guid=sub_name
                    )
            except:
                pass
            finally:
                if sub_key is not None:
                    sub_key.Close()

        return results

    # Build list of con_name -> guid mappings.
    results = recurse_search(root_key)
    root_key.Close()

    # Look up interface names.
    root_key = winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards",
        0,
        winreg.KEY_READ
    )

    # con_name -> {"guid": ..., "if_name": ...}
    infos = {}
    for sub_offset in range(0, winreg.QueryInfoKey(root_key)[0]):
        sub_name = winreg.EnumKey(root_key, sub_offset)
        sub_key = None
        found_guid = found_if_name = ""
        try:
            sub_key = winreg.OpenKey(root_key, sub_name)
            found_guid = winreg.QueryValueEx(sub_key, "ServiceName")[0]
            found_if_name = winreg.QueryValueEx(sub_key, "Description")[0]
        except:
            pass
        finally:
            if sub_key is not None:
                sub_key.Close()

        for result in results:
            con_name, saved_guid = result
            if saved_guid == found_guid:
                infos[con_name] = {
                    "guid": saved_guid,
                    "if_name": found_if_name
                }

    root_key.Close()
    return infos

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

