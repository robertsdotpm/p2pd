import re
import asyncio
import winreg

from .net import *
from .cmd_tools import *
from .ip_range import IPRange

def parse_wmic_list(entry):
    if not len(entry):
        return []
        
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
    def show_info(af, msg):
        p = "({[^{}]+})?\s+(.+? {0}) {2,}([0-9]+)\s+({[^{}]+})\s+([^\s]+)\s+({[^{}]+})"
        out = re.findall(p, msg)
        results = []
        for match_group in out:
            gw_ips, if_name, if_index, if_ips, mac, guid = match_group
            gw_ips = parse_wmic_list(gw_ips)
            if_ips = parse_wmic_list(if_ips)
            
            # Determine if interface isdefault for any AF.
            defaults = []
            for af in VALID_AFS:
                if len(gw_ips[af]):
                    defaults.append(af)
            
            # Record interface results.
            results.append({
                # TODO: 
                "con_name": None,
                "guid": guid,
                "name": if_name,
                "no": int(if_index),
                "mac": mac,
                "addr": parse_wmic_addrs(if_ips),
                "gws": parse_wmic_addrs(gw_ips),
                "defaults": defaults,
            })
        print(out)
        
    return results
        
async def workspace():
    print("test")
    c = "wmic nicconfig where IPEnabled=true get Description, IPAddress, DefaultIPGateway, Index, MACAddress, SettingID"
    msg = await cmd(c)
    print(msg)
    out = WMICParse.show_info(None, msg)
    print(out)
    
loop = asyncio.get_event_loop()
print(loop)
loop.run_until_complete(workspace())
        
        

    
