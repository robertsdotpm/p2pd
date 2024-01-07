import re
from p2pd import *

async def get_mac_mixed(if_name):
    win_p = f"[0-9]+\s*[.]+([^.\r\n]+)\s*[.]+"
    win_f = lambda x: re.findall(win_p + re.escape(if_name), x)[0]
    vectors = {
        "Linux": [
            f"cat /sys/class/net/{if_name}/address",
            lambda x: x
        ],
        "OpenBSD": [
            f"ifconfig {if_name} | egrep 'lladdr|ether'",
            lambda x: re.findall("\s+[a-zA-Z]+\s+([^\s]+)", x)[0]
        ],
        "Windows": [
            "route print",
            win_f
        ]
    }
    vectors["Darwin"] = vectors["OpenBSD"]
    os_name = platform.system()
    if os_name not in vectors:
        return None
    
    lookup_cmd, proc_f = vectors[os_name]
    out = await cmd(lookup_cmd)
    out = proc_f(out).strip()
    out = out.replace(" ", "-")
    out = out.replace(":", "-")
    return out

async def test_mac():
    out = await get_mac_mixed("Intel(R) Wi-Fi 6E AX211 160MHz")
    print(out, end="")

async_test(test_mac)