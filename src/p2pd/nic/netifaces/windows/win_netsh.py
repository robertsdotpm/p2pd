import re
import asyncio
import winreg

from ....net.net_utils import *
from ....utility.cmd_tools import *
from ....net.ip_range import IPRange

class NetshParse():
    # netsh interface ipv4 show interfaces
    # netsh interface ipv6 show interfaces
    # if_index: 
    @staticmethod
    def show_interfaces(af, msg):
        p = r"([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([a-z0-9]+)\s+([^\r\n]+)"
        out = re.findall(p, msg)
        results = {}
        for match_group in out:
            if_index, metric, mtu, state, name = match_group
            if if_index not in results:
                results[if_index] = {
                    "if_index": if_index,
                    "metric": metric,
                    "mtu": mtu,
                    "state": state,
                    "con_name": name
                }

        return [af, "ifs", results]
    
    # netsh interface ipv4 show ipaddresses
    # netsh interface ipv6 show addresses
    # if_index: ...
    @staticmethod
    def show_addresses(af, msg):
        msg = re.sub(r"%[0-9]+", "", msg)

        # Regex patterns that can match address information.
        # The pattern looks for the start of the interface line.
        # To tether it so it doesn't just match all text.
        p = r"[Ii]nterface\s+([0-9]+)[\s\S]+?[\r\n]([a-zA-Z0-9]+)\s+([a-zA-Z0-9]+)\s+([a-zA-Z0-9]+)\s+([a-zA-Z0-9]+)\s+((?=\S*[0-9]+\S*)([a-fA-F0-9:.]+))"

        # Build a table of all address info for each interface.
        # The table is indexed by interface no / if_index.
        results = {}
        while 1:
            # Find a valid address line for an interface
            addr_infos = re.findall(p, msg)
            if not len(addr_infos):
                break

            for addr_info in addr_infos:
                # Unpack the result.
                if_index, addr_type, dad_state, valid_life, pref_life, addr = addr_info[:6]
                if if_index not in results:
                    results[if_index] = []

                # Record details as a keyed record.
                results[if_index].append({
                    "addr_type": addr_type,
                    "dad_state": dad_state,
                    "valid_life": valid_life,
                    "pref_life": pref_life,
                    "addr": addr
                })

                # Remove the interface address line from the string.
                # Otherwise the regex will match the same result.
                #print(msg)
                msg = re.sub(p, fstr("Interface {0}\r\n", (if_index,)), msg, count=1)

        return [af, "addrs", results]
    
    # netsh interface ipv4 show route
    # netsh interface ipv6 show route
    # Routes also show subnet for interface addresses.
    @staticmethod
    def show_route(af, msg):
        p = r"([a-zA-Z0-9]+)\s+([a-zA-Z0-9]+)\s+([0-9]+)\s+([a-zA-Z0-9.:%\/]+)\s+([0-9]+)\s+([^\r\n]+)"
        out = re.findall(p, msg)
        results = {}
        for match_group in out:
            publish, rtype, metric, prefix, if_index, con_name = match_group
            if if_index not in results:
                results[if_index] = []

            results[if_index].append({
                "publish": publish,
                "rtype": rtype,
                "metric": metric,
                "prefix": prefix,
                "con_name": con_name
            })

        return [af, "routes", results]
    
    # route print
    # Also has ipv6 results.
    # if_index: ... if_name, mac
    @staticmethod
    def show_mac(af, msg):
        p = r"([0-9]+)\s*[.]{2,}([0-9a-fA-F ]+)[ .]+([^\r\n]+)[\r\n]"
        out = re.findall(p, msg)
        results = {"default": {IP4: None, IP6: None}}
        for match_group in out:
            if_index, mac, if_name = match_group
            mac = mac.strip().lower()
            mac = mac.replace(" ", "-")
            results[if_index] = {
                "if_name": if_name,
                "mac": mac
            }

        # Setup entries for default gateways IP4.
        p = r"0[.]0[.]0[.]0\s+0[.]0[.]0[.]0\s+([^\s]+)\s+([^\s]+)\s+[0-9]+"
        out = re.findall(p, msg)
        if len(out):
            gw_ip, if_ip = out[0]
            results["default"][IP4] = {
                "gw_ip": gw_ip.strip(),
                "if_ip": if_ip.strip()
            }

        # Setup entries for default gateways IP6.
        p = r"[0-9]+\s+[0-9]+\s+::\/0\s+([^\s]+)"
        out = re.findall(p, msg)
        if len(out):
            gw_ip = out[0]
            results["default"][IP6] = {
                "gw_ip": gw_ip.strip()
            }

        return [af, "macs", results]
    
    # ipconfig /all
    # mac: {ip4: ..., IP6: ...}
    @staticmethod
    def show_gws(af, msg):
        p = r"[pP]hysical[ ]+[aA]ddress[^:]+:([^\r\n]+)[\r\n][\s\S]+?[dD]efault[ ]+[gG]ateway[^:]+:((?:\s*[a-fA-F0-9:.%]+[\r\n])(?:\s*[a-fA-F0-9:.%]+[\r\n])?)"
        sections = msg.split("\r\n\r\n")

        results = {}
        for section in sections:
            out = re.findall(p, section)
            for match_group in out:
                mac, gws = match_group
                mac = mac.strip().lower()
                gws = gws.strip()
                gws = gws.split()
                af_gws = {IP4: None, IP6: None}

                success = False
                for offset in range(0, len(gws)):
                    try:
                        gw = ip_strip_if(gws[offset])
                        gw_ipr = IPRange(ip=gw)
                        af_gws[gw_ipr.af] = gw
                    except Exception:
                        continue
                    success = True

                if not success:
                    continue

                results[mac] = af_gws

        return [af, "gws", results]

async def do_netsh_cmds():
    parser = NetshParse()
    cmd_vectors = [
        [
            parser.show_interfaces,
            {
                IP4: "interfaces",
                IP6: "interfaces"
            }
        ],
        [
            parser.show_addresses,
            {
                IP4: "ipaddresses",
                IP6: "addresses"
            }
        ],
        [
            parser.show_route,
            {
                IP4: "route",
                IP6: "route"
            }
        ],
        [
            parser.show_mac,
            {
                IP4: "route print",
            },
            False
        ],
        [
            parser.show_gws,
            {
                IP4: "ipconfig /all",
            },
            False
        ]
    ]

    async def helper(af, cmd_val, func):
        out = await cmd(cmd_val)
        return func(af, out)

    tasks = []
    for cmd_vector in cmd_vectors:
        for af in [IP4, IP6]:
            if af in cmd_vector[1]:
                show_val = cmd_vector[1][af]
                af_val = "ipv4" if af == IP4 else "ipv6"
                if len(cmd_vector) > 2:
                    cmd_val = show_val
                else:
                    cmd_val = fstr("netsh interface {0} show {1}", (af_val, show_val,))

                tasks.append(helper(af, cmd_val, cmd_vector[0]))

    # Execute all netsh commands concurrently.
    results = await safe_gather(*tasks)

    # Combine results to make them easier to process.
    info = {}
    for result in results:
        af, k, v = result
        if k == "ifs":
            info["ifs"] = v
            continue

        if k not in info:
            info[k] = {}

        info[k][af] = v

    return info


"""
Net name is very specifically not the interface name or
its description. Examples of the net name are 'local area network.'
Examples of an interface name 'Intel ... ethernet v10'.

"""
def win_con_name_lookup():
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
                    if re.match(r"{[^{}]+}", sub_name) == None:
                        continue

                    results += recurse_search(
                        sub_key,
                        guid=sub_name
                    )
            except Exception:
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
        except Exception:
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

def get_cidr_from_route_infos(needle_ip, route_infos):
    netmask = None
    cidr = 128
    for route_info in route_infos:
        prefix_ip, prefix_cidr = route_info["prefix"].split("/")
        prefix_cidr = int(prefix_cidr)
        if not prefix_cidr:
            continue

        prefix_ipr = IPRange(prefix_ip, cidr=prefix_cidr)
        masked_needle_net = toggle_host_bits(
            prefix_ipr.netmask,
            needle_ip
        )
        masked_needle_ipr = IPRange(masked_needle_net, cidr=prefix_cidr)

        if prefix_ipr == masked_needle_ipr:
            if prefix_cidr <= cidr:
                cidr = prefix_cidr
                netmask = prefix_ipr.netmask

    return [cidr, netmask]

async def if_infos_from_netsh():
    con_table = win_con_name_lookup()
    out = await do_netsh_cmds()

    if_infos = []
    for if_index in out["ifs"]:
        if_info = out["ifs"][if_index]
        con_name = if_info["con_name"]

        addr_info = {IP4: [], IP6: []}
        for af in [IP4, IP6]:
            if if_index not in out["addrs"][af]:
                continue

            for found_addr in out["addrs"][af][if_index]:
                cidr, netmask = get_cidr_from_route_infos(
                    found_addr["addr"],
                    out["routes"][af][if_index]
                )

                addr = {
                    "addr": found_addr["addr"],
                    "af": af,
                    "cidr": cidr,
                    "netmask": netmask
                }
                addr_info[af].append(addr)

        if con_name not in con_table:
            continue

        if if_index not in out["macs"][IP4]:
            continue

        mac = out["macs"][IP4][if_index]["mac"].rstrip().lower()
        if mac not in out["gws"][IP4]:
            continue
        gws = out["gws"][IP4][mac]

        # Determine if interface isdefault for any AF.
        defaults = []
        for test_af in [IP4, IP6]:
            af_default = out["macs"][IP4]["default"][test_af]
            if af_default is None:
                continue

            af_gw = gws[test_af]
            if af_gw is None:
                continue

            if IPRange(af_gw) == IPRange(af_default["gw_ip"]):
                defaults.append(test_af)

        result = {
            "con_name": con_name,
            "guid": con_table[con_name]["guid"],
            "name": con_table[con_name]["if_name"],
            "no": int(if_index),
            "mac": mac,
            "addr": addr_info,
            "gws": gws,
            "defaults": defaults
        }

        if_infos.append(result)

    return if_infos
