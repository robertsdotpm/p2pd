from ...utility.utils import *
from ..net_utils import *
from .bind_rules import *


"""
Mostly this class will not be used directly by users.
It's code is also shitty for res. Routes have superseeded this.
"""
class Bind():
    def __init__(self, interface, af, port=0, ips=None, leave_none=0):
        #if IS_DEBUG:
        #assert("Interface" in str(type(interface)))
        self.__name__ = "Bind"
        self.ips = ips
        self.interface = interface
        self.af = af
        self.resolved = False
        self.bind_port = port

        # Will store a tuple that can be passed to bind.
        self._bind_tups = ()
        if not hasattr(self, "bind"):
            self.bind = bind_closure(self)

    def __await__(self):
        return self.bind().__await__()

    async def res(self):
        return await self.bind()

    async def start(self):
        await self.res()

    def bind_tup(self, port=None, flag=NIC_BIND):
        # Handle loopback support.
        if flag == LOOPBACK_BIND:
            if self.af == IP6:
                return ("::1", self.bind_port)
            else:
                return ("127.0.0.1", self.bind_port)

        # Spawn a new copy of the bind tup (if needed.)
        tup = self._bind_tups
        if port is not None:
            tup = copy.deepcopy(tup)
            tup[1] = port

        # IP may not be set if invalid type of IP passed to Bind
        # and then the wrong flag type was used with it.
        if tup[0] is None:
            e = "Bind ip is none. Possibly an invalid IP "
            e += "(private and not public or visa versa) "
            e += "was passed to Bind for IPv6 causing no "
            e += "IP for the right type to be set. "
            e += "Also possible there were no link locals."
            raise Exception(e)

        #log("> binding to tup = {}".format(tup))
        return tup

    def supported(self):
        return [self.af]
    
"""
Provides an interface that allows for bind() to be called
with its own parameters as a Route object method. Allows
the IP and port used to be accessed inside it as properties.
Otherwise defaults to using IP and port already set in class
which would only be the case if this method were used from a
Bind object and not a Route object. So a lot of hacks here.
But that's the API I wanted.
"""
def bind_closure(self):
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