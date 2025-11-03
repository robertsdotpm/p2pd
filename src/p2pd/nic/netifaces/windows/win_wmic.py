import re
import asyncio
import winreg

from ....net.net_utils import *
from ....utility.cmd_tools import *
from ....net.ip_range import IPRange

def parse_wmic_list(entry):
    if not len(entry):
        return []
        
    if entry[0] == "{":
        if entry[1] not in ("'", '"'):
            entry = '{"' + entry[1:-1] + '"}'

    entry = entry.replace('{', '[')
    entry = entry.replace('}', ']')

    return eval(entry)
    
def parse_wmic_addrs(addrs):
    addr_info = {IP4: [], IP6: []}
    for addr in addrs:
        ipr = IPRange(addr)
        addr_info[ipr.af].append({
            "addr": addr,
            "af": ipr.af,
            
            # Both just placeholders / incorrect.
            # TODO: get real values in the future.
            "cidr": ipr.cidr,
            "netmask": ipr.netmask,
        })
        
    return addr_info    

class WMICParse():
    @staticmethod
    def show_main(af, msg):
        p = r"({[^{}]+})?\s{2,}([^{}\r\n]+?) {2,}([0-9]+)\s+"
        p += r"({[^{}]+})\s+([^\s]+)\s+({[^{}]+})"
        out = re.findall(p, msg)
        results = []
        for match_group in out:
            # Name the match group fields.
            gw_ips, if_name, if_index, if_ips, mac, guid = match_group
            gw_ips = parse_wmic_list(gw_ips)
            if_ips = parse_wmic_list(if_ips)
            
            # Put GWs into right format for netifaces.
            gws = {IP4: None, IP6: None}
            gws_addrs = parse_wmic_addrs(gw_ips)
            for af in VALID_AFS:
                if len(gws_addrs[af]):
                    gws[af] = gws_addrs[af][0]["addr"]
                    break
            
            # Record interface results.
            results.append({
                "guid": guid,
                "name": if_name,
                "no": int(if_index),
                "mac": mac,
                "addr": parse_wmic_addrs(if_ips),
                "gws": gws,
                
                # Todo:
                "defaults": None,
                "con_name": None,
            })

        return [af, "main", results]
        
    @staticmethod
    def show_con_names(af, msg):
        p = r"\s{0}([0-9]+)\s+([^\r\n]+?) {2,}\s*"
        out = re.findall(p, msg)
        results = {}
        for match_group in out:
            if_index, name = match_group
            if if_index not in results:
                results[if_index] = {
                    "if_index": if_index,
                    "con_name": name
                }
        
        return [af, "con_names", results]
    
    # route print
    # Also has ipv6 results.
    # if_index: ... if_name, mac
    @staticmethod
    def show_routes(af, msg):
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

        return [af, "routes", results]
        
async def do_wmic_cmds():
    parser = WMICParse()
    cmd_vectors = [
        [
            parser.show_main,
            {
                IP4: "wmic nicconfig where IPEnabled=true get Description, IPAddress, DefaultIPGateway, Index, MACAddress, SettingID",
            },
            False
        ],
        [
            parser.show_con_names,
            {
                IP4: "wmic nic get Index, NetConnectionID",
            },
            False
        ],
        [
            parser.show_routes,
            {
                IP4: "route print",
            },
            False
        ],
    ]
    
    async def helper(cmd_txt, out_handler):
        out = await cmd(cmd_txt)
        return out_handler(None, out)
    
    # Build list of commands to run.
    tasks = []
    for vector in cmd_vectors:
        out_handler, cmd_meta, _ = vector
        task = helper(cmd_meta[IP4], out_handler)
        tasks.append(task)
        
    # Run commands concurrently or not.
    return await safe_gather(*tasks)
    
async def if_infos_from_wmic():
    # Get NIC info from different WMIC cmds.
    results = await do_wmic_cmds()
        
    # Index by key.
    by_name = {}
    for result in results:
        _, k, v = result
        by_name[k] = v
        
    # Consolidate everything into main.
    ret = []
    for entry in by_name["main"]:
        # Special index for NICs.
        if_index = str(entry["no"])
        
        # Skip inactive connections.
        if if_index not in by_name["con_names"]:
            continue
        
        # Record con_name for an if.
        con_name = by_name["con_names"][if_index]["con_name"]
        entry["con_name"] = con_name
        
        # Fill in default gateway defaults.
        defaults = []
        for af in [IP4, IP6]:
            gw_info = by_name["routes"]["default"]
            if gw_info[af] is None:
                continue
                
            # Does gw interface IP match this IF?
            gw_if_ipr = IPRange(gw_info[af]["if_ip"])
            for addr_info in entry["addr"][af]:
                if_ipr = IPRange(addr_info["addr"])
                if if_ipr == gw_if_ipr:
                    defaults.append(af)
                    break
        
        # List of AFs this if is the main interface for.
        entry["defaults"] = defaults     
        ret.append(entry)
        
    # Show results.
    return ret
        

async def workspace():

    results = await if_infos_from_wmic()
    print(results)

    
if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(workspace())
        
        

    
