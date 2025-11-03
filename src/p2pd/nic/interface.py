import platform
import pprint
from ..errors import *
from ..settings import *
from .route.route_pool import *
from .route.route_utils import *
from .nat.nat_utils import *
from .route.route_table import *
from ..protocol.stun.stun_client import *
from .nat.nat_test import nic_load_nat
from .load_interface import *
from ..entrypoint import *

# Used for specifying the interface for sending out packets on
# in TCP streams and UDP streams.
# Note: number of bad STUN servers means timeout should be higher.
# Maybe make this proportional to last server freshness age.
class Interface():
    def __init__(self, name=None, stack=DUEL_STACK, nat=None, netifaces=None, timeout=4):
        super().__init__()
        self.__name__ = "Interface"
        self.resolved = False
        self.netiface_index = None
        self.id = self.mac = self.nic_no = None
        self.nat = nat or nat_info()
        self.name = name
        self.rp = {IP4: RoutePool(), IP6: RoutePool()}
        self.v4_lan_ips = []
        self.guid = None
        self.netifaces = netifaces or Interface.get_netifaces()
        self.timeout = timeout

        # Check NAT is valid if set.
        if nat is not None:
            assert(isinstance(nat, dict))
            assert(nat.keys() == nat_info().keys())

        # Can provide a stack type to skip processing unsupported AFs.
        # Otherwise all AFs are checked when start() is called.
        self.stack = stack
        assert(self.stack in VALID_STACKS)

    async def start(self, netifaces=None, min_agree=2, max_agree=5, timeout=4):
        # Declared in load_interface.py.
        return await load_interface(
            nic=self,
            netifaces=netifaces,
            min_agree=min_agree,
            max_agree=max_agree,
            timeout=timeout,
        )
    
    async def load_nat(self, nat_tests=5, delta_tests=12, timeout=4):
        # Try main decentralized NAT test approach.
        nat_type, delta = await nic_load_nat(
            self,
            nat_tests,
            delta_tests,
            timeout=timeout
        )
            
        # Load NAT type and delta info.
        # On a server should be open.
        nat = nat_info(nat_type, delta)
        return self.set_nat(nat)
    
    def set_nat(self, nat):
        assert(isinstance(nat, dict))
        assert(nat.keys() == nat_info().keys())
        self.nat = nat
        return nat
    
    def get_scope_id(self):
        assert(self.resolved)

        # Interface specified by no on windows.
        if platform.system() == "Windows":
            return self.nic_no
        else:
            # Other platforms just use the name
            return self.name

    def nic(self, af):
        # Sanity check.
        if self.resolved:
            assert(af in self.what_afs())
        if self.rp != {} and len(self.rp[af].routes):
            return self.route(af).nic()

    def route(self, af=None, bind_port=0):
        # Sanity check.
        if self.resolved:
            af = af or self.supported()[0]
            assert(af in self.what_afs())

        # Main route is first.
        if af in self.rp:
            if len(self.rp[af].routes):
                return copy.deepcopy(self.rp[af].routes[0])

        raise Exception(fstr("No route for {0} found.", (af,)))

    def is_default_patch(self, af, gws=None):
        return True

    """
    Using a default list of gateways like this has a small
    performance advantage but the cost is if the interfaces list
    changes at run time like a wifi network disconnecting then
    the is_default function may give the incorrect result. There
    should be a way to detect loss of internet connection though.
    """
    def is_default(self, af, gws=None):
        return is_nic_default(self, af, gws)
    
    def supported(self, skip_resolve=0):
        if not skip_resolve:
            assert(self.resolved)

        if self.stack == UNKNOWN_STACK:
            raise Exception("Unknown stack")

        if self.stack == DUEL_STACK:
            return sorted([IP4, IP6])
        else:
            return sorted([self.stack])

    def what_afs(self):
        assert(self.resolved)
        return self.supported()
    
    def __await__(self):
        return self.start(timeout=self.timeout).__await__()

    def to_dict(self):
        return nic_to_dict(self)

    @staticmethod
    def get_netifaces():
        return None

    @staticmethod
    def list():
        return Interface.get_netifaces().interfaces()

    @staticmethod
    def from_dict(d):
        return nic_from_dict(d, Interface)

    # Make this interface printable because it's useful.
    def __str__(self):
        return pprint.pformat(self.to_dict())

    # Show a representation of this object.
    def __repr__(self):
        nic_info = str(self)
        return "Interface.from_dict(%s)" % (nic_info)

    # Pickle.
    def __getstate__(self):
        return self.to_dict()

    # Unpickle.
    def __setstate__(self, state):
        o = self.from_dict(state)
        self.__dict__ = o.__dict__

if __name__ == "__main__": # pragma: no cover
    async def test_interface():
        #out = await cmd("route print")
        return
        out = await nt_route_print("Realtek Gaming 2.5GbE Family Controller")
        print(out)
        return

        i = Interface(AF_ANY)   
        await i.start()
        #af = i.stack if i.stack != DUEL_STACK else IP4
        #b = Bind(i, af)

        return
        if1 = await Interface("enp3s0").start()
        if2 = await Interface("wlp2s0").start()
        ifs = Interfaces([if1, if2])
        print(ifs.by_af)

    async_test(test_interface)

