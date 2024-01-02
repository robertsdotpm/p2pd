import re
import asyncio
import pprint

from .net import *
from .cmd_tools import *

class NetshParse():
    # netsh interface ipv4 show interfaces
    # netsh interface ipv6 show interfaces
    @staticmethod
    def show_interfaces(af, msg):
        p = "([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([a-z0-9]+)\s+([^\r\n]+)"
        out = re.findall(p, msg)
        results = []
        for match_group in out:
            if_index, metric, mtu, state, name = match_group
            results.append({
                "if_index": if_index,
                "metric": metric,
                "mtu": mtu,
                "state": state,
                "name": name
            })

        return [af, "ifs", results]
    
    # netsh interface ipv4 show ipaddresses
    # netsh interface ipv6 show addresses
    @staticmethod
    def show_addresses(af, msg):
        msg = re.sub("%[0-9]+", "", msg)

        # Regex patterns that can match address information.
        # The pattern looks for the start of the interface line.
        # To tether it so it doesn't just match all text.
        p = "[Ii]nterface\s+([0-9]+)[\s\S]+?[\r\n]([a-zA-Z0-9]+)\s+([a-zA-Z0-9]+)\s+([a-zA-Z0-9]+)\s+([a-zA-Z0-9]+)\s+((?=\S*[0-9]+\S*)([a-fA-F0-9:.]+))"

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
                msg = re.sub(p, f"Interface {if_index}\r\n", msg, count=1)

        return [af, "addrs", results]
    
    # netsh interface ipv4 show route
    # netsh interface ipv6 show route
    # Routes also show subnet for interface addresses.
    @staticmethod
    def show_route(af, msg):
        p = "([a-zA-Z0-9]+)\s+([a-zA-Z0-9]+)\s+([0-9]+)\s+([a-zA-Z0-9.:%\/]+)\s+([0-9]+)\s+([^\r\n]+)"
        out = re.findall(p, msg)
        results = {}
        for match_group in out:
            publish, rtype, metric, prefix, if_index, if_name = match_group
            if if_index not in results:
                results[if_index] = []

            results[if_index].append({
                "publish": publish,
                "rtype": rtype,
                "metric": metric,
                "prefix": prefix,
                "if_name": if_name
            })

        return [af, "routes", results]
    
    # netsh interface ipv4 show ipnettomedia
    # Also has ipv6 results.
    @staticmethod
    def show_mac(af, msg):
        p = "(?:(?=\S*[-:]+\S*)(?=\S*[0-9a-fA-F]+\S*))([0-9a-fA-F-:]+)\s+([^\s]+)\s+([^\s]+)\s+([^\r\n]+)"
        out = re.findall(p, msg)
        results = {}
        for match_group in out:
            mac_addr, ip_addr, ip_type, if_name = match_group
            if if_name not in results:
                results[if_name] = []

            results[if_name].append({
                "mac": mac_addr,
                "ip": ip_addr,
                "type": ip_type,
            })

        return [af, "macs", results]

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
                IP4: "ipnettomedia",
            }
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
                cmd_val = f"netsh interface {af_val} show {show_val}"
                tasks.append(helper(af, cmd_val, cmd_vector[0]))

    results = await asyncio.gather(*tasks)
    info = {}
    for result in results:
        af, k, v = result
        if k not in info:
            info[k] = {}

        info[k][af] = v

    return info

async_test(do_netsh_cmds)