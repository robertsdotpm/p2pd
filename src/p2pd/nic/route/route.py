"""
This is my attempt to visualize the association between private, NIC
addresses and public WAN addresses on a network interface. I have
learned the following information about network addresses:
 
    * A NIC can have one or more addresses.
    * A NIC can be assigned a block or range of addresses.
    * A NIC doesn't have to use private addresses. It's common for
    server hosts to assign the external addresses that belong
    to the server in such a way that they are used by the NIC.
    In such a case: the NICs addresses would be the same as
    how it was viewed from the external Internet.
    * A NIC can use public addresses that it doesn't own on
    the Internet. This is very bad because it means that these
    addresses will be unreachable on the Internet on that machine.
    NICs should ideally use private addresses. Or stick to IPs
    they actually can route to themselves on the Internet.
    * A NIC defines a "default" gateway to route packets to
    the Internet (which is given by network 0.0.0.0 in IPv4.)
    " The NIC can actually specify multiple default gateways.
    Each entry is a route in the route table. It will have a
    'metric' indicates its 'speed.' The route with the
    the lowest metric is chosen to route packets. TCP/IP may
    adjust the metric of routes based on network conditions.
    Thus, if there are multiple gateways for a NIC then its
    possible for the external WAN address to change under
    high network load. This is not really ideal.
 
The purpose of this module is to have easy access to the
external addresses of the machine and any associated NIC
addresses needed for Bind calls in order to use them. I
use the following simple rules to make this possible:
 
    1. All private addresses for a NIC form a group. This
    group points to the same external address for that NIC.
    2. Any public addresses are tested using STUN. If STUN
    sees the same result as the public address then the
    address is considered public and forms its own route.
    If STUN reports a different result then the address is
    being improperly used for a private NIC address. It
    thus gets added to the private group in step 1.
    3. If there is a block of public addresses to check
    only the first address is checked. If success then
    I assume the whole block is valid. Ranges of
    addresses are fully supported.
 
When it comes to complex routing tables that have
strange setups with multiple default gateways for
a NIC I am for now ignoring this possibility. I
don't consider myself an expert on networking (its
much more complex than it appears) but to directly
leverage routes in a routing table seems to me that
it would require having to work on the ethernet layer.
Something much more painful than regular sockets.

One last thing to note about routing tables: there is
a flag portion that indicates whether a route is 'up.'
If this means 'online' and 'reachable' it would be
really useful to check this to determine if a stack
supported IPv6 or IPv4 rather than trying to test it
first using STUN and waiting for a long time out.

Other:
When it comes to IPs assigned to a NIC its possible
to assign 'public' IPs to it directly. You often
see this setup on servers. In this case you know
that not only can you use the public addresses
directly in bind() calls -- but you know that
the server's corresponding external IP will be
what was used in the bind() call. Very useful.

The trouble is that network interfaces happily
accept 'external IPs' or IPs outside of the
typical 'private IP' range for use on a NIC or
LAN network. Obviously this is a very bad idea
but in the software it has the result of
potentially assuming that an IP would end up
resulting in a particular external IP being used.

The situation is not desirable when building
a picture of a network's basic routing makeup.
I've thought about the problem and I don't see
a way to solve it other than to measure how a
route's external address is perceived from the
outside world. Such a solution is not ideal but
at least it only has to be done once.
"""

import copy
import ipaddress
import pprint
from functools import total_ordering
from ...net.ip_range import *
from ..netifaces.netiface_extra import *
from ...protocol.upnp.upnp import *
from ...net.address import *
from ...net.bind.bind import *

@total_ordering
class Route(Bind):
    def __init__(self, af, nic_ips, ext_ips, interface=None, ext_check=1):
        # Sanity tests.
        assert(af in VALID_AFS)
        assert(isinstance(nic_ips, list))
        assert(isinstance(ext_ips, list))
        assert(len(ext_ips))
        assert(len(nic_ips))

        # Check value and type of ext_ip.
        assert(isinstance(ext_ips[0], IPRange))
        assert(ext_ips[0].i_ip) # IP must not be 0.
        assert(ext_ips[0].af == af)

        # Check NIC values.
        for nic_ipr in nic_ips:
            assert(isinstance(nic_ipr, IPRange))
            assert(nic_ipr.af == af)

        # Allow ext to be private if check is disabled.
        # Needed to allow for conversion from a Bind to a Route.
        if ext_check:
            assert(ext_ips[0].is_public)

        # Interface my be None.
        super().__init__(interface, af, leave_none=1)
        self.__name__ = "Route"
        self.af = af
        self.nic_ips = nic_ips or []
        self.ext_ips = ext_ips or []
        self.link_locals = []

        # Maybe None for loopback interface.
        self.interface = interface
        self.route_pool = self.route_offset = self.host_offset = None

    def __await__(self):
        return self.bind().__await__()
    
    def set_link_locals(self, link_locals):
        self.link_locals = link_locals
    
    async def Address(self, dest, port):
        return (dest, port)

    async def forward(self, ip=None, port=None, proto="TCP"):
        assert(self.resolved)
        port = port or self.bind_port
        if ip is None:
            if self.af == IP4:
                ip = self.nic()
            else:
                ip = self.ext()
        
        src_tup = (
            ip,
            port,
        )

        return await port_forward(
            af=self.af,
            interface=self.interface,
            ext_port=port,
            src_tup=src_tup,
            desc=fstr("P2PD {0}", (hash(src_tup),))[0:8],
            proto=proto
        )

    # TODO: document this? You probably don't want to use this.
    async def rebind(self, port=0, ips=None):
        route = copy.deepcopy(self)
        await route.bind(port=port, ips=ips)
        return route

    # A little bit nicer than accessing fields directly
    # every time just to bind to a route.
    def nic(self):
        """
        Try to select a link local (if one exists) for IPv6.
        The IPv6 proto requires at least one link local
        for core protocols like router advertisements and
        such to work properly. Assuming that IPv6 support is
        enabled on a host. If not this will raise an Exception.
        """

        """
        if self.af == IP6:
            for ipr in self.nic_ips:
                if ipr.is_private:
                    return ipr_norm(ipr)

            raise Exception("> Route.nic() with af=6 found no link-locals.")
        """

        return ipr_norm(self.nic_ips[0])

    def ext(self):
        """
        # Patch for unroutable IPv6 used as LAN IPs.
        # This is only visable to the bind() caller.
        if self.af == IP6:
            print("here")
            for stack_f in inspect.stack():
                f_name = stack_f[3]
                if f_name == "bind":
                    if self.ext_ips[0] not in self.nic_ips:
                        print("bbb")
                        for nic_ipr in self.nic_ips:
                            print("ccc")
                            print(str(nic_ipr[0]))
                            if "fe80" != ip_norm(nic_ipr[0])[:4]:
                                return ip_norm(nic_ipr[0])
        """

        return ipr_norm(self.ext_ips[0])
    
    def link_local(self):
        return ipr_norm(self.link_locals[0])

    # Test if a given IPRange is in the nic_ips list.
    def has_nic_ip(self, ipr):
        for nic_ipr in self.nic_ips:
            if nic_ipr == ipr:
                return True

        return False

    def set_offsets(self, route_offset, host_offset=None):
        self.route_offset = route_offset
        self.host_offset = host_offset

    def link_route_pool(self, route_pool):
        self.route_pool = route_pool

    def _check_extended(self):
        if self.route_pool is None:
            raise Exception("e = route_pool not linked.")

    @staticmethod
    def _convert_other(other):
        if isinstance(other, Route):
            if len(other.ext_ips):
                return other.ext_ips[0]
            else:
                return []

        if isinstance(other, IPRange):
            return other

        if isinstance(other, bytes):
            other = to_s(other)

        if isinstance(other, (str, int)):
            ipa = ipaddress.ip_address(other)
            ipr = IPRange(other, cidr=CIDR_WAN)
            return ipr

        if isinstance(other, IPA_TYPES):
            af = v_to_af(other.version)
            ipr = IPRange(other, cidr=CIDR_WAN)
            return ipr

        raise NotImplemented("Cannot convert other to IPRange in route.")

    def bad_len(self, other):
        if not len(self) or not len(other):
            return True
        else:
            return False

    # Get a list of N routes that don't use this WAN IP.
    # Incrementally adjusts route offset so its efficent.
    def alt(self, limit, exclusions=None):
        # Init storage vars.
        # Check the class has been mapped to a RoutePool.
        self._check_extended()
        routes = []
        n = 0

        # Return limit results.
        for route in self.route_pool:
            # Skip self.
            if route == self:
                continue

            # If exclude is not then get alternate route to self.
            if exclusions is not None:
                if route in exclusions:
                    continue

            # Make list of results.
            # There may be a huge number of hosts so stop at limit.
            routes.append(route)
            n += 1
            if n >= limit:
                break

        return routes

    def to_dict(self):
        nic_ips = []
        ext_ips = []
        list_infos =  [[nic_ips, self.nic_ips], [ext_ips, self.ext_ips]]
        for list_info in list_infos:
            dest_list, src_list = list_info
            for ipr in src_list:
                dest_list.append(ipr.to_dict())

        link_local_ips = []
        for ipr in self.link_locals:
            link_local_ips.append(ipr.to_dict())

        return {
            "af": int(self.af),
            "nic_ips": nic_ips,
            "ext_ips": ext_ips,
            "link_local_ips": link_local_ips,
        }

    @staticmethod
    def from_dict(d):
        nic_ips = []
        ext_ips = []
        list_info =  [[nic_ips, d["nic_ips"]], [ext_ips, d["ext_ips"]]]
        for dest_list, src_list in list_info:
            for ipr_d in src_list:
                ipr = IPRange.from_dict(ipr_d)
                dest_list.append(ipr)

        af = IP4 if d["af"] == IP4 else IP6
        route = Route(
            af=af,
            nic_ips=nic_ips,
            ext_ips=ext_ips
        )

        link_locals = []
        for ipr_d in d["link_local_ips"]:
            ipr = IPRange.from_dict(ipr_d)
            link_locals.append(ipr)

        route.link_locals = link_locals
        return route

    # Pickle.
    def __getstate__(self):
        return self.to_dict()

    # Unpickle.
    def __setstate__(self, state):
        o = self.from_dict(state)
        self.__dict__ = o.__dict__

    # Route != [Route, ...] = [Route, ...]
    # (max len = len(right operand))
    def __ne__(self, other):
        if self is other:
            return False

        # Compare selfs WAN to others WAN.
        if isinstance(other, Route):
            return self.ext_ips[0] != other.ext_ips[0]

        # Otherwise get a list of routes, not matching the ones provided.
        if not isinstance(other, list):
            raise NotImplemented("Route != ? not implemented")
        else:
            return self.alt(limit=len(other), exclude_wans=other)

    # Return first route that doesn't use this same WAN IP.
    # Incrementally adjusts route offset so its efficent.
    # not Route = route_info (with different WAN to left operand.)
    def __invert__(self):
        self._check_extended()
        for route in self.route_pool:
            # If route has same external addr then skip.
            if route == self:
                continue

            return route

        return None

    def __len__(self):
        if len(self.ext_ips) == 0:
            return 0
        else:
            return len(self.ext_ips[0])

    def __repr__(self):
        return fstr("Route.from_dict({0})", (str(self),))

    def __str__(self):
        return pprint.pformat(self.to_dict())

    def __eq__(self, other):
        other = Route._convert_other(other)
        if self.bad_len(other):
            return False

        return self.ext_ips[0] == other

    def __contains__(self, other):
        return self == other

    def __lt__(self, other):
        other = self._convert_other(other)
        if self.bad_len(other):
            return False

        return self.ext_ips[0] < other

    def __deepcopy__(self, memo):
        # Will fall back to the __deepcopy__ of IPRange.
        nic_ips = [copy.deepcopy(nic_ip) for nic_ip in self.nic_ips]
        ext_ips = [copy.deepcopy(ext_ips) for ext_ips in self.ext_ips]

        # Probably does nothing. YOLO.
        route = Route(self.af, nic_ips, ext_ips, self.interface)
        route.set_offsets(self.route_offset, self.host_offset)
        if self.route_pool is not None:
            route.link_route_pool(self.route_pool)
        route.ips = self.ips
        route.bind_port = self.bind_port
        route._bind_tups = copy.deepcopy(self._bind_tups)
        route.resolved = self.resolved
        route.set_link_locals(copy.deepcopy(self.link_locals))

        return route