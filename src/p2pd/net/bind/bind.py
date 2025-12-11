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
            self.bind = bind_closure(self, binder_async)

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
    
