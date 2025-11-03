from ...utility.utils import *
from ..net_utils import *

def ip6_patch_bind_ip(bind_ip, nic_id):
    # Add interface descriptor if it's link local.
    if to_s(bind_ip[0:2]).lower() in ["fe", "fd"]:
        # Interface specified by no on windows.
        if platform.system() == "Windows":
            bind_ip = "%s%%%d" % (
                bind_ip,
                nic_id
            )
        else:
            # Other platforms just use the name
            bind_ip = "%s%%%s" % (
                bind_ip,
                nic_id
            )

    return bind_ip

async def get_high_port_socket(route, socket_factory, sock_type=TCP):
    # Minimal config to pass socket factory.
    conf = {
        "broadcast": False,
        "linger": None,
        "sock_proto": 0,
        "reuse_addr": True
    }

    # Get a new socket bound to a high order port.
    for i in range(0, 20):
        n = rand_rang(2000, MAX_PORT - 1000)
        await route.bind(n)
        try:
            s = await socket_factory(
                route,
                sock_type=sock_type,
                conf=conf
            )
        except:
            continue

        return s, n
    
    raise Exception("Could not bind high range port.")