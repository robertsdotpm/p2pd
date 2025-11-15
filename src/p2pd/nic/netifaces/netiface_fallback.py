from ...net.net_utils import *

def load_if_info_fallback(nic):
    # Just guess name.
    # Getting this wrong will only break IPv6 link-local binds.
    nic.id = nic.name = nic.name or "eth0"
    nic.netiface_index = 0
    nic.type = INTERFACE_ETHERNET

    # Get IP of default route.
    ips = {
        # Google IPs. Nothing special.
        IP4: "142.250.70.206",
        IP6: "2404:6800:4015:803::200e",
    }

    # Build a table of default interface IPs based on con success.
    # Supported stack changes based on success.
    if_addrs = {}
    for af in VALID_AFS:
        try:
            s = socket.create_connection((ips[af], 80))
            if_addrs[s.family] = s.getsockname()[0][:]
            s.close()
        except Exception:
            continue

    # Same API as netifaces.
    class NetifaceShim():
        def __init__(self, if_addrs):
            self.if_addrs = if_addrs

        def interfaces(self):
            return [self.name]

        def ifaddresses(self, name):
            ret = {
                # MAC address (blanket)
                # 17 = netifaces.AF_LINK enum.
                AF_LINK: [
                    {
                        'addr': '',
                        'broadcast': 'ff:ff:ff:ff:ff:ff'
                    }
                ],
            }

            for af in self.if_addrs:
                ret[af] = [
                    {
                        "addr": self.if_addrs[af],
                        "netmask": "0"
                    }
                ]

            return ret
        
    nic.netifaces = NetifaceShim(if_addrs)
    nic.is_default = nic.is_default_patch