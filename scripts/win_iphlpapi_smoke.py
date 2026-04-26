"""
Quick smoke for win_iphlpapi.get_interfaces on whichever Windows host
runs it. Upload to XP and run:

    scp scripts/win_iphlpapi_smoke.py matthew@10.0.1.132:C:/win_iphlpapi_smoke.py
    ssh matthew@10.0.1.132 'C:\\py3\\python.exe C:\\win_iphlpapi_smoke.py'

Expected output: one block per adapter with friendly name, MAC, and
each detected v4/v6 unicast address with prefix length.
"""

import sys

from aionetiface.nic.netifaces.windows.win_iphlpapi import (
    get_interfaces,
    is_supported,
    to_netifaces_shape,
)


def main():
    print("python: {0}".format(sys.version.replace("\n", " ")))
    print("platform: {0}".format(sys.platform))
    print("is_supported: {0}".format(is_supported()))

    if not is_supported():
        print("not running on Windows; nothing to enumerate")
        return

    interfaces = get_interfaces()
    print("\nfound {0} adapter(s)".format(len(interfaces)))
    for name, info in interfaces.items():
        print("\n  {0!r}".format(name))
        print("    description : {0!r}".format(info["description"]))
        print("    ifindex     : {0}".format(info["ifindex"]))
        print("    ipv6_ifindex: {0}".format(info["ipv6_ifindex"]))
        print("    mac         : {0}".format(info["mac"]))

        import socket
        for af, label in ((socket.AF_INET, "v4"), (socket.AF_INET6, "v6")):
            entries = info[af]
            if not entries:
                continue
            print("    {0} addrs    :".format(label))
            for e in entries:
                print("      - {0}/{1}".format(e["addr"], e["prefix"]))

    print("\nnetifaces-shape projection (compat shim):")
    shaped = to_netifaces_shape(interfaces)
    for name, per_af in list(shaped.items())[:3]:
        print("  {0!r} -> {1}".format(name, per_af))


if __name__ == "__main__":
    main()
