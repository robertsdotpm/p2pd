"""
This module is a drop-in replacement for netifaces on Windows.
Usage is simply:
    from p2pd import *
    async def main():
        netifaces = await init_p2pd() 

The pypi netifaces module has several problems on Windows OS':

1. It requires a distribution of VS C++ Build Tools 20**.
Having users install the right build tools to get the software
working is complex and error-prone. It also makes packaging
software that uses netifaces much more difficult.

2. On recent versions of Windows it displays meaningless
strings of GUIDs over network interface names. Consequently,
one has to do a series of reg hacks, privilege elevations,
and patches to use the library with human-readable names.

The most portable way to do complex operations on Windows
seems to be to use powershell scripting. Looking up certain
registry keys isn't guaranteed to work as the locations may
change between versions. The networking tools available in
cmd.exe are now being phased out in favor of the tools
available in powershell. Powershell is now widely supported
even on older Windows OS.

The downside to using powershell to obtain relevent NIC
information is it's slow. A process needs to be spawned
for each new command. In order to prevent errors on certain
Windows versions concurrency also has to be disabled. This
doesn't seem to effect speed too much but the code is many
times slower than netiface. Nevertheless, it's more
portable and doesn't require privilege elevations to get
human-readable network interface descriptions.

Speedups:

I've added a new feature to obtain all the networking info
from a single powershell script. The program will attempt
to use this script if powershell is unrestricted. If it
fails to load interfaces with regular commands it will
try relaunch with a UAC prompt, unrestrict powershell,
then attempt to run the script in powershell. 

Notes:
    - These commands don't seem to require special permissions.
    - They need to use double quotes or the command won't run.
    - Tested as working with execution policy = restricted.
"""

import re
from .ip_range import *
from .cmd_tools import *

CMD_TIMEOUT = 10

IFS_PS1 = """
# Load default interface for IPv4 and IPv6.
$v4_default = Find-NetRoute -RemoteIPAddress 0.0.0.0 -erroraction 'silentlycontinue' | Format-List -Property ifIndex
$v6_default = Find-NetRoute -RemoteIPAddress :: -erroraction 'silentlycontinue' | Format-List -Property ifIndex
if($v4_default -eq $null){
    $v4_default = "null"
}
if($v6_default -eq $null){
    $v6_default = "null"
}

# Show them if any.
echo("4444444444")
echo($v4_default)
echo("4444444444")
echo("6666666666")
echo($v6_default)
echo("6666666666")

# Load interfaces and associated addresses.
$ifs = Get-NetAdapter -physical -erroraction 'silentlycontinue' | where status -eq up 
Foreach($iface in $ifs){
    # Get first hop for the iface for both AFs.
    $v4gw = (Get-NetRoute "0.0.0.0/0" -InterfaceIndex $iface.ifIndex  -erroraction 'silentlycontinue').NextHop 
    $v6gw = (Get-NetRoute "::/0" -InterfaceIndex $iface.ifIndex  -erroraction 'silentlycontinue').NextHop
    if($v4gw -eq $null){
        $v4gw = "null"
    }

    if($v6gw -eq $null){
        $v6gw = "null"
    }

    # Build a list of IPs.
    $ips = [System.Collections.ArrayList]::new()
    $addrs = Get-NetIPAddress -InterfaceIndex $iface.ifIndex
    Foreach($addr in $addrs){
        $ips += $addr.IPAddress
    }

    # Save them as new property calues.
    $iface | Add-Member -NotePropertyName v4GW -NotePropertyValue $v4gw
    $iface | Add-Member -NotePropertyName v6GW -NotePropertyValue $v6gw

    # Output this interface info with it's addresses.
    $out = $iface | Format-List -Property InterfaceDescription,ifIndex,InterfaceGuid,MacAddress,v4GW,v6GW
    echo($out)
    echo($ips)
}
"""

async def load_ifs_from_ps1():
    # Get all interface details as one big script.
    out = await nt_pshell(IFS_PS1)

    # Load default interface by if_index.
    default_ifs = {IP4: None, IP6: None}
    if_defaults_by_index = {}
    for v in [4, 6]:
        # No to AF.
        af = v_to_af(v)

        # Regex to extract the interface no for the AF.
        delim = str(v) * 10
        p = f"{delim}[\s\S]*ifIndex\s*:\s*([0-9]+)[\s\S]*{delim}"
        if_index = re.findall(p, out)

        # Save it in a loopup table.
        if len(if_index):
            if_index = to_n(if_index[0])

            # Save it by AF.
            default_ifs[af] = if_index

            # Make a list to store AF by if_index.
            if if_index not in if_defaults_by_index:
                if_defaults_by_index[if_index] = []

            # Save AF by if_index.
            if_defaults_by_index[if_index].append(af)

    # Extract interface details.
    p = "InterfaceDescription *: *([^\r\n]+?) *[\r\n]+ifIndex *: *([0-9]+?) *[\r\n]+InterfaceGuid *: *([^\r\n]+?) *[\r\n]+MacAddress *: *([^\r\n]+?) *[\r\n]+v4GW *: *([^\r\n]+?) *[\r\n]+v6GW *: *([^ ]+?)[\s]+((?:[0-9a-f.:%]+ *[\r\n]*)+)"
    re_results = re.findall(p, out)

    # Index the results into a dict.
    if_infos = []
    if len(re_results):
        for r in re_results:
            if_index = to_n(r[1])
            if_info = {
                "guid": r[2],
                "name": r[0],
                "no": if_index,
                "mac": r[3],

                # Placeholders.
                "addr": None,
                "gws": { 
                    IP4: None if r[4] == "null" else r[4],
                    IP6: None if r[5] == "null" else r[5]
                },
                "defaults": []
            }

            # Set defaults.
            if if_index in if_defaults_by_index:
                if_info["defaults"] = if_defaults_by_index[if_index]

            # Process address info.
            addr_info = { IP4: [], IP6: [] }
            addr_s = r[6].replace(' ', '')
            addr_list = addr_s.splitlines(False)
            for addr in addr_list:
                # Skip blank IPs.
                if addr == '':
                    continue

                # Convert to netifaces format.
                addr = ip_strip_cidr(ip_strip_if(addr))
                ipr = IPRange(addr)
                addr_info[ipr.af].append({
                    "addr": addr,
                    "af": ipr.af,
                    "cidr": ipr.cidr,
                    "netmask": ipr.netmask
                })

            # Save addresses.
            if_info["addr"] = addr_info

            # Save info.
            if_infos.append(if_info)

    """
    If no route found for a given address family set the first
    interface as the default interface for that AF.
    """
    for af in VALID_AFS:
        if default_ifs[af] is None:
            if len(if_infos):
                if if_infos[0]["gws"][af] is not None:
                    if_infos[0]["defaults"].append(af)


    return if_infos

async def get_default_gw_by_if_index(af, if_index):
    dest_ip = "0.0.0.0/0" if af == IP4 else "::/0"
    cmd_str = '{} "(Get-NetRoute {} -InterfaceIndex {}).NextHop"'
    cmd_str = cmd_str.format("powershell", dest_ip, if_index)

    # Execute the command.
    try:
        out = await cmd(cmd_str, timeout=CMD_TIMEOUT)
    except Exception:
        return None


    if out is None:
        return None

    # Return the string if it's a valid IP.
    out = out.strip()
    try:
        ip_f(out)
        return out
    except:
        log(f"{out}")
        return None

async def get_addr_info_by_if_index(if_index):
    addr = { IP4: [], IP6: [] }
    cmd_str = 'powershell "Get-NetIPAddress -InterfaceIndex {}"'
    cmd_str = cmd_str.format(if_index)
    try:
        out = await cmd(cmd_str, timeout=CMD_TIMEOUT)
    except Exception:
        return addr

    try:
        addr_infos = re.findall(
            "IPAddress\s*:\s*([^\s]*)[\s\S]*?AddressFamily\s*:\s*([^\s]+)[\s\S]*?PrefixLength\s*:\s([0-9]+)",
            out
        )

        for addr_info in addr_infos:
            ip_val, af_family, cidr = addr_info
            cidr = int(cidr)
            if af_family == "IPv4":
                af = IP4
            if af_family == "IPv6":
                af = IP6

            addr[af].append({
                "addr": ip_val,
                "af": af,
                "cidr": cidr
            })
    except Exception:
        log_exception()
        return addr

    return addr

async def get_default_iface_by_af(af):
    if af == IP4:
        any_offset = 0
    if af == IP6:
        any_offset = 1

    any_addr_list = ["0.0.0.0", "::"]
    dest_ip = any_addr_list[any_offset]
    cmd_buf = 'powershell "Find-NetRoute -RemoteIPAddress {}"'
    cmd_buf = cmd_buf.format(dest_ip)
    try:
        out = await cmd(cmd_buf, timeout=CMD_TIMEOUT)
    except:
        return None

    try:
        if_index_str = re.findall("InterfaceIndex\s*:\s*([0-9]+)", out)
        if len(if_index_str):
            return int(if_index_str[0])
        else:
            # If an AF is not support an error is thrown
            # and the pattern above won't match anything.
            return None
    except Exception:
        log_exception()
        return None

def extract_if_fields(ifs_str):
    results = []
    try:
        if_info_matches = re.findall("InterfaceDescription\s*:\s([^\r\n]*?)[\r\n]+ifIndex\s*:\s*([0-9]+)\s*InterfaceGuid\s*:\s*([^\r\n]+)\s*MacAddress\s*:\s*([^\s]+)\s*", ifs_str)
        if len(if_info_matches):
            for if_info_match in if_info_matches:
                if_desc, if_index, guid, mac_addr = if_info_match
                if_index = int(if_index)
                results.append({
                    "guid": guid,
                    "name": if_desc,
                    "no": if_index,
                    "mac": mac_addr,

                    # Placeholders.
                    "addr": None,
                    "gws": { IP4: None, IP6: None },
                    "defaults": None
                })
    except Exception:
        log_exception()
        return results

    return results

# Get list of net adaptors via powershell.
# Ignore hidden adapters. Non-physical or down.
# Specify desc and index to show full entry.
async def get_ifaces():
    try:
        out = await cmd('powershell "Get-NetAdapter -physical | where status -eq up  | Format-List -Property InterfaceDescription,ifIndex,InterfaceGuid,MacAddress"', timeout=CMD_TIMEOUT)
    except Exception:
        log_exception()
        out = ""

    return out

async def win_load_interface_state(if_results):
    # Lookup whether an1
    if_defaults_by_index = {}
    af_index = {}
    async def set_ip4_if_index():
        af_index[IP4] = await get_default_iface_by_af(IP4)
    async def set_ip6_if_index():
        af_index[IP6] = await get_default_iface_by_af(IP6)

    # Execute the above functions.
    tasks =  [
        set_ip4_if_index(),
        set_ip6_if_index(),
    ]
    for task in tasks:
        await task

    # Set the AFs the interface is the default for.
    if af_index[IP4] or af_index[IP6]:
        if af_index[IP4]:
            if_defaults_by_index[af_index[IP4]] = [IP4]

        if af_index[IP6]:
            if_defaults_by_index[af_index[IP6]] = [IP6]

        if af_index[IP4] == af_index[IP6]:
            if_defaults_by_index[af_index[IP4]] = [IP4, IP6]

    # Parse output lines from Get-Adapter.
    if_tasks = []
    by_guid_index = {}
    for result in if_results:
        async def if_task_func():
            try:
                if_index = result["no"]
                guid = result["guid"]

                # Default interface for these address families.
                default_for_afs = []
                if if_index in if_defaults_by_index:
                    default_for_afs = if_defaults_by_index[if_index]

                result["defaults"] = default_for_afs

                # Otherwise it's worth saving.
                by_guid_index[guid] = result

                # Get address information.
                async def set_addr():
                    by_guid_index[guid]["addr"] = await get_addr_info_by_if_index(if_index)

                # Get default gateways.
                async def set_ip4_gw():
                    by_guid_index[guid]["gws"][IP4] = await get_default_gw_by_if_index(IP4, if_index)
                async def set_ip6_gw():
                    by_guid_index[guid]["gws"][IP6] = await get_default_gw_by_if_index(IP6, if_index)

                # Execute the above tasks.
                sub_tasks = [
                    set_addr(),
                    set_ip4_gw(),
                    set_ip6_gw()
                ]
                for task in sub_tasks:
                    await task
            except Exception:
                log_exception()
                return

        if_tasks.append(if_task_func())

    for if_task in if_tasks:
        await if_task

    return by_guid_index

def win_set_gateways(by_guid_index):
    gws = {
        "default": { },
        int(IP4): [],
        int(IP6): []
    }

    for _, addr_info in by_guid_index.items():
        # Set defaults for different AFs.
        for af in addr_info["defaults"]:
            # If no gateway for af found skip.
            if addr_info["gws"][af] is None:
                continue

            # Default field for gateway.
            gws["default"][int(af)] = (
                addr_info["gws"][af],
                addr_info["name"]
            )

            # Add to list of gateways.
            if len(addr_info["gws"][af]):
                is_default = af in addr_info["defaults"]
                gws[int(af)].append(
                    (
                        addr_info["gws"][af],
                        addr_info["name"],
                        is_default
                    )
                )

    return gws

class Netifaces():
    AF_INET = IP4
    AF_INET6 = IP6
    AF_LINK = 18

    def __init__(self):
        pass

    async def start(self):
        # Can run powershell scripts or not.
        is_restricted = await is_pshell_restricted()

        # Use multiple commands to load interface details.
        if is_restricted:
            ifs_str = await get_ifaces()
            if_results = extract_if_fields(ifs_str)
            self.by_guid_index = await win_load_interface_state(if_results)

            # Fallback to load_ifs_from_ps1.
            # Will need to try disable restricted.
            if self.by_guid_index == {}:
                try:
                    if not is_root():
                        win_uac()
                    else:
                        await nt_set_pshell_unrestricted()
                        is_restricted = await is_pshell_restricted()
                except Exception:
                    log_exception()
        
        # Load netifaces using a PS1 script.
        if not is_restricted:
            # Use a single script to load all info at once.
            if_infos = await load_ifs_from_ps1()
            self.by_guid_index = {}
            for if_info in if_infos:
                self.by_guid_index[if_info["guid"]] = if_info

        # Sanity check.
        if self.by_guid_index == {}:
            raise Exception("Unable to load interfaces.")

        # Setup name index.
        self.by_name_index = {}
        for _, if_info in self.by_guid_index.items():
            name = if_info["name"]
            self.by_name_index[name] = if_info

        # Save main gateways used.
        self.gws = win_set_gateways(self.by_guid_index)
        return self

    def gateways(self):
        return self.gws

    def if_info(self, if_name):
        return self.by_name_index[if_name]

    def guid(self, if_name):
        if_info = self.if_info(if_name)
        return if_info["guid"]

    def nic_no(self, if_name):
        if_info = self.if_info(if_name)
        return if_info["no"]

    def ifaddresses(self, if_name):
        if_info = self.by_name_index[if_name]
        addr_format = {
            int(IP4): [],
            int(IP6): [],

            # Netifaces AF_LINK = MAC address.
            Netifaces.AF_LINK: [
                {
                    "addr": if_info["mac"]
                }
            ]
        }

        # Add addresses in netiface format.
        for af in [IP4, IP6]:
            for addr_info in if_info["addr"][af]:
                addr = {
                    "addr": addr_info["addr"],
                    "netmask": cidr_to_netmask(
                        addr_info["cidr"],
                        af
                    )
                }

                addr_format[int(af)].append(addr)

        return addr_format

    def interfaces(self):
        ifs = []
        for _, if_info in self.by_guid_index.items():
            ifs.append(if_info["name"])

        return ifs