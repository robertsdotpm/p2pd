import re
import platform
from .net import *

async def windows_get_route_table(af):
    table = []
    if af == IP4:
        cmd_buf = 'powershell "Get-NetRoute -AddressFamily IPv4"'
    if af == IP6:
        cmd_buf = 'powershell "Get-NetRoute -AddressFamily IPv6"'

    out = await cmd(cmd_buf, timeout=4)
    p = "([0-9]+)\s+([^\s]+)\s+([^\s]+)\s+([0-9]+)\s+([0-9]+)\s+([^\s]+)[\r\n]*"
    results = re.findall(p, out)
    for result in results:
        entry = {
            "if_index": int(result[0]),
            "if": int(result[0]),
            "dest": result[1],
            "next_hop": result[2],
            "route_metric": int(result[3]),
            "if_metric": int(result[4]),
            "policy_store": result[5]
        }

        table.append(entry)

    return table

async def linux_get_route_table(af):
    table = []
    bin_path = "/usr/sbin/route"
    if af == IP4:
        cmd_buf = "{} -4".format(bin_path)
        out = await cmd(cmd_buf, timeout=4)
        p = "([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([-0-9]+)\s+([-0-9]+)\s+([-0-9]+)\s+([^\r\n]+)[\r\n]*"
        results = re.findall(p, out)
        for result in results:
            entry = {
                "dest": result[0],
                "gw": result[1],
                "gen_mask": result[2],
                "flag": result[3],
                "metric": int(result[4]),
                "ref": int(result[5]),
                "use": int(result[6]),
                "if": result[7]
            }

            table.append(entry)

    if af == IP6:
        cmd_buf = "{} -6".format(bin_path)
        out = await cmd(cmd_buf, timeout=4)
        p = "([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([-0-9]+)\s+([-0-9]+)\s+([-0-9]+)\s+([^\r\n]+)[\r\n]*"
        results = re.findall(p, out)
        for result in results:
            entry = {
                "dest": result[0],
                "next_hop": result[1],
                "flag": result[2],
                "metric": int(result[3]),
                "ref": int(result[4]),
                "use": int(result[5]),
                "if": result[6]
            }

            table.append(entry)

    return table

async def darwin_get_route_table(af):
    table = []
    p = "([^\r\n]+?)[ ]+([^\r\n]+?)[ ]+([^\r\n]+?)[ ]+([^\r\n ]+)[ ]*(([^\r\n]+)[ ]*)?[\r\n]+"
    if af == IP4:
        cmd_buf = "netstat -rn -f inet"
    if af == IP6:
        cmd_buf = "netstat -rn -f inet6"

    out = await cmd(cmd_buf, timeout=4)
    results = re.findall(p, out)
    for result in results:
        entry = {
            "dest": result[0],
            "gw": result[1],
            "flags": result[2],
            "if": result[3],
            "expiry": result[4]
        }

        table.append(entry)

    return table

async def get_route_table(af):
    if platform.system() == "Windows":
        return await windows_get_route_table(af)

    if platform.system() == "Linux":
        return await linux_get_route_table(af)

    if platform.system() in ["Darwin", "FreeBSD"]:
        return await darwin_get_route_table(af)

    return []

def find_rt_entry(dest, if_name, table):
    for entry in table:
        if entry["dest"] != dest:
            continue

        if entry["if"] != if_name:
            continue

        return entry

async def darwin_is_internet_if(if_name):
    def is_internet_if(table):
        # Find default entry for iface.
        default_entry = find_rt_entry("default", if_name, table)
        if default_entry is None:
            return False

        # Check flags for entry.
        if 'U' not in default_entry["flags"]:
            return False
        if 'G' not in default_entry["flags"]:
            return False

        return True

    for af in VALID_AFS:
        table = await get_route_table(af)
        if is_internet_if(table):
            return True

    return False

async def linux_is_internet_if(if_name):
    def is_internet_if(table, af):
        if af == IP6:
            for entry in table:
                if entry["if"] != if_name:
                    continue

                cidr = int(entry["dest"].split("/")[-1])
                if cidr != 128:
                    continue

                if entry["next_hop"] != "[::]":
                    continue

                try:
                    ip_s = ip_norm(entry["dest"])
                except:
                    continue

                ip_obj = ip_f(ip_s)
                if ip_obj.is_private:
                    continue

                return True

        if af == IP4:
            dest = "default"
            entry = find_rt_entry(dest, if_name, table)
            if entry is None:
                return False

            if entry["gen_mask"] == "0.0.0.0":
                return True

        return False

    for af in VALID_AFS:
        table = await get_route_table(af)
        if is_internet_if(table, af):
            return True

    return False

async def windows_is_internet_if(if_index):
    def is_internet_if(table, af):
        if af == IP4:
            dest = "0.0.0.0/0"
        if af == IP6:
            dest = "::/0" # Probably what it will be.

        return find_rt_entry(dest, if_index, table) is not None

    for af in VALID_AFS:
        table = await get_route_table(af)
        if is_internet_if(table, af):
            return True

    return False

async def is_internet_if(if_name):
    if platform.system() == "Linux":
        return await linux_is_internet_if(if_name)

    if platform.system() in ["Darwin", "FreeBSD"]:
        return await darwin_is_internet_if(if_name)

    if platform.system() == "Windows":
        return await windows_is_internet_if(if_name)

    return False

if __name__ == "__main__": # pragma: no cover
    from .interface import Interface
    async def test_route_table():
        i = Interface()
        if i.nic_no:
            r = await is_internet_if(i.nic_no)
        else:
            r = await is_internet_if(i.name)
        print(r)

    async_test(test_route_table)

