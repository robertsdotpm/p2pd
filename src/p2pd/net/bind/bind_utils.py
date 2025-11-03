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

"""
Provides an interface that allows for bind() to be called
with its own parameters as a Route object method. Allows
the IP and port used to be accessed inside it as properties.
Otherwise defaults to using IP and port already set in class
which would only be the case if this method were used from a
Bind object and not a Route object. So a lot of hacks here.
But that's the API I wanted.
"""
def bind_closure(self, binder):
    async def bind(port=None, ips=None):
        if self.resolved:
            return
        
        # Bind parameters.
        port = port or self.bind_port
        ips = ips or self.ips
        if ips is None:
            # Bind parent.
            if hasattr(self, "interface") and self.interface is not None:
                route = self.interface.route(self.af)
                ips = route.nic()
            else:
                # Being inherited from route.
                ips = self.nic()

        # Number or name - platform specific.
        if self.interface is not None:
            nic_id = self.interface.id
        else:
            nic_id = None

        # Get bind tuple for NIC bind.
        self._bind_tups = await binder(
            af=self.af, ip=ips, port=port, nic_id=nic_id
        )

        # Save state.
        self.bind_port = port
        self.resolved = True
        return self
        
    return bind