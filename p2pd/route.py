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
"""

import asyncio
import copy
import ipaddress
import pprint
import inspect
from functools import total_ordering, cmp_to_key
from .ip_range import *
from .netiface_extra import *
from .upnp import *
from .address import *

"""
As there's only one STUN server in the preview release the
consensus code is not needed.
"""
ROUTE_CONSENSUS = [1, 1]

# Allows referencing a list of routes as if all WAN IPs
# were at their own index regardless of if they're in ranges.
# Will be very slow if there's a lot of hosts.
class RoutePoolIter():
    def __init__(self, rp, reverse=False):
        self.rp = rp
        self.reverse = reverse
        self.host_p = 0
        self.route_offset = 0

        # Point to the end route -- we're counting backwards.
        if self.reverse:
            self.route_offset = len(self.rp.routes) - 1

    def __iter__(self):
        return self

    def __next__(self):
        # Avoid overflow.
        if self.host_p >= self.rp.wan_hosts:
            raise StopIteration

        # Offset used for absolute position of WAN host.
        if self.reverse == False:
            host_offset = self.host_p
        else:
            host_offset = (len(self.rp) - 1) - self.host_p
        
        # Get a route object encapsulating that WAN host.
        route = self.rp.get_route_info(
            self.route_offset,
            self.host_p
        )

        # Adjust position of pointers.
        self.host_p += 1
        if self.reverse == False:
            if self.host_p >= self.rp.len_list[self.route_offset]:
                if self.route_offset < len(self.rp.routes) - 1:
                    self.route_offset += 1
        else:
            if self.host_p >= self.rp.len_list[self.route_offset]:
                if self.route_offset:
                    self.route_offset -= 1

        # Return the result.
        return route

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
        self.af = af
        self.nic_ips = nic_ips or []
        self.ext_ips = ext_ips or []
        self.link_locals = []

        # Maybe None for loopback interface.
        self.interface = interface
        self.route_pool = self.route_offset = self.host_offset = None

    """
    async def bind(self, port=None, ips=None):
        if self.af == IP4:
            # Patch for non-routable public IPv6s.
            print("aaa")
            print(self.ext_ips[0])
            old_ext = self.ext
            if self.ext_ips[0] not in self.nic_ips:
                print("bbb")
                for nic_ipr in self.nic_ips:
                    print(str(nic_ipr[0]))
                    if "fe80" != str(nic_ipr[0])[:4]:
                        self.ext = lambda: str(nic_ipr[0])
                        break

            self.ext = old_ext

        await bind_closure(self)(port=port, ips=ips)

    

        print(self._bind_tups)
        """

    def __await__(self):
        return self.bind().__await__()
    
    def set_link_locals(self, link_locals):
        self.link_locals = link_locals
    
    async def Address(self, dest, port):
        return await Address(dest, port, self)

    async def forward(self, port=None, proto="TCP"):
        assert(self.resolved)
        port = port or self.bind_port
        ip = self.nic()
        src_addr = await Address(
            ip,
            port,
            self
        ).res()
        return await port_forward(
            interface=self.interface,
            ext_port=port,
            src_addr=src_addr,
            desc=f"P2PD {hash(src_addr.tup)}"[0:8],
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

        return {
            "af": int(self.af),
            "nic_ips": nic_ips,
            "ext_ips": ext_ips,
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
        return Route(
            af=af,
            nic_ips=nic_ips,
            ext_ips=ext_ips
        )

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
        return f"Route.from_dict({str(self)})"

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

class RoutePool():
    def __init__(self, routes=None, link_locals=None):
        self.routes = routes or []
        self.link_locals = link_locals or []

        # Avoid duplicates in routes.
        for route in self.routes:
            if route not in self.routes:
                self.routes.append(route)

        # Make a list of the address size for WAN portions of routes.
        # Such information will be used for dereferencing routes.
        self.len_list = []
        self.wan_hosts = 0
        for i in range(0, len(self.routes)):
            # Link route to route pool.
            self.routes[i].link_route_pool(self)
            self.routes[i].set_offsets(route_offset=i)

            # No WAN ipr section defined.
            if not len(self.routes[i].ext_ips):
                self.len_list.append(self.wan_hosts)
                continue

            # Append val to len_list = current hosts + wan hosts at route.
            next_val = self.wan_hosts + len(self.routes[i].ext_ips[0])
            self.len_list.append(next_val)
            self.wan_hosts = next_val

        # Index into the routes list.
        self.route_index = 0

        # Simulate 'removing' past elements.
        self.pop_pointer = 0

    def to_dict(self):
        routes = []
        for route in self.routes:
            routes.append(route.to_dict())

        return routes

    @staticmethod
    def from_dict(route_dicts):
        routes = []
        for route_dict in route_dicts:
            routes.append(Route.from_dict(route_dict))

        return RoutePool(routes)

    # Pickle.
    def __getstate__(self):
        return self.to_dict()

    # Unpickle.
    def __setstate__(self, state):
        o = self.from_dict(state)
        self.__dict__ = o.__dict__

    def locate(self, other):
        for route in self.routes:
            if route == other:
                return route

        return None

    # Is a route in this route pool?
    def __contains__(self, other):
        route = self.locate(other)
        if route is not None:
            return True
        else:
            return False

    # Simulate fetching a route off a stack of routes.
    # Just hides certain pointer offsets when indexing, lel.
    def pop(self):
        if self.pop_pointer >= self.wan_hosts:
            raise Exception("No more routes.")

        ret = self[self.pop_pointer]
        self.pop_pointer += 1

        return ret

    def get_route_info(self, route_offset, abs_host_offset):
        # Route to use for the WAN addresses.
        assert(route_offset <= (len(self.routes) - 1))
        route = self.routes[route_offset]
        
        # Convert host_offset to a index inside route's WAN subnet.
        prev_len = self.len_list[route_offset - 1] if route_offset else 0
        rel_host_offset = abs_host_offset - prev_len
        assert(rel_host_offset <= self.len_list[route_offset] - 1)

        # Get references to member objs.
        wan_ipr = route.ext_ips[0]
        nic_ipr = route.nic_ips[0]

        # For pub ranges assigned to NIC -- they will line up.
        # For N or more private addressess -> a WAN = probably won't.
        # In such a case it doesn't matter as any NIC IP = the same WAN.
        assert(rel_host_offset + 1 <= self.wan_hosts)
        assert(len(wan_ipr))
        assert(len(nic_ipr))
        rel_host_offset = rel_host_offset % self.wan_hosts
        
        # Build a route corrosponding to these offsets.
        wan_ip = IPRange(str(wan_ipr[rel_host_offset]), cidr=CIDR_WAN)
        new_route = Route(
            af=route.af,
            nic_ips=copy.deepcopy(route.nic_ips),
            ext_ips=[wan_ip],
            interface=route.interface
        )
        new_route.set_offsets(route_offset, abs_host_offset)
        new_route.link_route_pool(self)

        return new_route

    def __len__(self):
        return self.wan_hosts

    def __getitem__(self, key):
        # Possible due to pop decreasing host no.
        if not self.wan_hosts:
            return []

        if isinstance(key, slice):
            start, stop, step = key.indices(len(self))
            return [self[i] for i in range(start, stop, step)]
        elif isinstance(key, int):
            # Convert negative index to positive.
            # Sorted_search doesn't work with negative indexex.
            if key < 0:
                key = key % self.wan_hosts

            route_offset = sorted_search(self.len_list, key + 1)
            if route_offset is None:
                return None
            else:
                return self.get_route_info(route_offset, key)
        elif isinstance(key, tuple):
            return [self[x] for x in key]
        else:
            raise TypeError('Invalid argument type: {}'.format(type(key)))

    def __iter__(self):
        return RoutePoolIter(self)

    def __reversed__(self):
        return RoutePoolIter(self, reverse=True)

def rp_from_fixed(fixed, interface, af): # pragma: no cover
    """
    [
        [
            nics [[ip, opt netmask], ...],
            exts [[ip]]
        ],
        route ...
    ]
    """

    routes = []
    for route in fixed:
        nic_iprs = []
        ext_iprs = []
        for meta in [[nic_iprs, route[0]], [ext_iprs, route[1]]]:
            dest, nic_infos = meta
            for nic_info in nic_infos:
                ip = nic_info[0]
                netmask = None
                if len(nic_info) == 2:
                    netmask = nic_info[1]

                ipr = IPRange(ip, netmask=netmask)
                dest.append(ipr)

        route = Route(af, nic_iprs, ext_iprs, interface)
        routes.append(route)

    return RoutePool(routes)

"""
When it comes to IPs assigned to a NIC its possible
to assign 'public' IPs to it directly. You often
see this setup on servers. In this case you know
that not only can you use the public addresses
directly in bind() calls -- but you know that
the server's corrosponding external IP will be
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
async def ipr_is_public(nic_ipr, stun_client, route_infos, stun_conf, is_default=False):
    # Use this IP for bind call.
    src_ip = ip_norm(str(nic_ipr[0]))
    log(F"using src_ip = {src_ip}, af = {stun_client.af} for STUN bind!")
    local_addr = await Bind(
        stun_client.interface,
        af=stun_client.af,
        port=0,
        ips=src_ip
    ).res()
    log(f"Bind obj = {local_addr}")

    # Get external IP and compare to bind IP.
    wan_ip = await stun_client.get_wan_ip(
        local_addr=local_addr,
        conf=stun_conf
    )
    log(f"Stun returned = {wan_ip}")
    if wan_ip is None:
        raise Exception("Unable to get wan IP.")

    # Record this wan_ip.
    ext_ipr = IPRange(wan_ip, cidr=CIDR_WAN)
    if ext_ipr not in route_infos:
        route_infos[ext_ipr] = []

    # Determine if public address is assigned to interface.
    if src_ip != wan_ip:
        # In a 'public range' but used privately.
        # Yes, this is silly but possible.
        nic_ipr.is_private = True
        nic_ipr.is_public = False
        if "default" not in route_infos:
            route_infos["default"] = ext_ipr
    else:
        # Otherwise routable, public IP used as a NIC address.
        # ext_ipr == nic_ipr.
        nic_ipr.is_private = False
        nic_ipr.is_public = True

    # Save details for this route.
    route_infos[ext_ipr].append(nic_ipr)

async def get_routes(interface, af, skip_resolve=False, skip_bind_test=False, netifaces=None, stun_client=None):
    from .stun_client import STUNClient, STUN_CONF

    # Settings to use for external addresses over STUN.
    if interface is not None:
        log(f">get routes for {interface.name} {af}")
        nic_id = interface.name
    else:
        nic_id = None

    # Route-specific config options for STUN.
    stun_conf = copy.deepcopy(STUN_CONF)
    stun_conf["retry_no"] = 2 # Slower but more fault-tolerant.
    stun_conf["consensus"] = ROUTE_CONSENSUS # N of M for a result.
    loop = asyncio.get_event_loop()
    link_locals = []
    route_infos = {}
    nic_iprs = []
    routes = []

    # Other important variables.
    stun_client = stun_client or STUNClient(interface, af=af)
    netifaces_af = af_to_netiface(af)
    if_addresses = netifaces.ifaddresses(nic_id)
    if netifaces_af in if_addresses:
        bound_addresses = if_addresses[netifaces_af]
        log(f"Testing {bound_addresses}")
        tasks = []
        first_private = True
        for info in bound_addresses:
            nic_ipr = await netiface_addr_to_ipr(af, info, interface, loop, skip_bind_test)
            log(f"Nic ipr in route = {nic_ipr}")
            if nic_ipr is None:
                log(f"Nic ipr is None so skipping")
                continue

            # Include link locals in their own set.
            # Todo: theres other prefixes like UNL.
            if ip_norm(nic_ipr[0])[:4] == "fe80":
                link_locals.append(nic_ipr)
                log(f"Addr is link local so skipping")
                continue

            # All private IPs go to the same route.
            # The interface has one external WAN IP.
            log(f"Nic ipr is private = {nic_ipr.is_private}")
            if nic_ipr.is_private:
                # Ensure the external address is fetched at least once
                # assuming there's only private addresses.
                # All private NICs will point to this.
                if first_private:
                    tasks.append(
                        async_wrap_errors(
                            ipr_is_public(nic_ipr, stun_client, route_infos, stun_conf),
                            timeout=10
                        )
                    )

                    first_private = False
                else:
                    nic_iprs.append(nic_ipr)
            else:
                if skip_resolve == False:
                    # Determine if this address is really public.
                    tasks.append(
                        async_wrap_errors(
                            ipr_is_public(nic_ipr, stun_client, route_infos, stun_conf),
                            timeout=10
                        )
                    )
                else:
                    # Assume IP is public and routable.
                    # Useful for manually configured interfaces.
                    nic_ipr.is_private = False
                    nic_ipr.is_public = True
                    route = Route(
                        af=af,
                        nic_ips=[nic_ipr],
                        ext_ips=[copy.deepcopy(nic_ipr)],
                        interface=stun_client.interface
                    )

                    routes.append(route)

        # Process pending tasks.
        if len(tasks):
            await asyncio.gather(*tasks)

            # Failure.
            if not len(route_infos):
                return [routes, link_locals]

            # Choose a random ext address for the default.
            if "default" not in route_infos:
                route_infos["default"] = list(route_infos.keys())[0]

            # Add private NIC iprs to default route.
            default_route = route_infos["default"]
            default_nics = route_infos[default_route]
            for nic_ipr in nic_iprs:
                default_nics.append(nic_ipr)

            # Default route will be added first.
            routes.append(Route(af, default_nics, [default_route], interface))
            del route_infos["default"]

            # Convert route infos to routes and save them.
            for ext_ipr in route_infos:
                if ext_ipr != default_route:
                    routes.append(
                        Route(
                            af,
                            route_infos[ext_ipr],
                            [ext_ipr],
                            interface
                        )
                    )

        # Add link locals to routes.
        log(f"Calling set link locals on routes {len(routes)}")
        [r.set_link_locals(link_locals) for r in routes]

    # Deterministically order routes list.
    cmp = lambda r1, r2: int(r1.ext_ips[0]) - int(r2.ext_ips[0])
    routes = sorted(routes, key=cmp_to_key(cmp))

    # Fallback to default if no route found.
    """
    It may make sense to run this concurrently and
    insert the route in the list if there's no duplicate route ext.
    """

    """
    Binding to any address lets the interface choose
    the default IP for the interface.
    This allows this address to be set first in the
    route list while still returning deterministic routes.
    """
    local_addr = await Bind(
        stun_client.interface,
        af=af,
        port=0,
        ips=ANY_ADDR_LOOKUP[af]
    ).res()

    # Get external IP and compare to bind IP.
    wan_ip = await stun_client.get_wan_ip(
        local_addr=local_addr,
        conf=stun_conf
    )

    """
    If the default route was found successfully then
    its used to check for duplicates in the route list
    which are removed. The default route is then
    inserted first in the route list which avoids
    bind issues on platforms that have 'strong route'
    selection behavior where they might ignore bind
    addresses for TCP.
    """
    default_route = None
    if wan_ip is not None:
        # Convert default details to a Route object.
        cidr = af_to_cidr(af)
        nic_ipr = IPRange(ANY_ADDR_LOOKUP[af], cidr=cidr)
        ext_ipr = IPRange(wan_ip, cidr=cidr)
        default_route = Route(af, [nic_ipr], [ext_ipr], interface)
    
        # Remove default route from routes list.
        cleaned_routes = []
        for route in routes:
            do_remove = False
            for ext_ipr in route.ext_ips:
                if len(ext_ipr) == 1:
                    if default_route.ext_ips[0] == ext_ipr:
                        default_route = route
                        do_remove = True
                        break

            if not do_remove:
                cleaned_routes.append(route)

        # Ensure that the default route is first.
        routes = [default_route] + cleaned_routes
        
    log(f"Link locals at end of load router = {link_locals}")
    return [routes, link_locals]

async def Routes(interface_list, af, netifaces, skip_resolve=False):
    # Optimization: check if an AF has a default gateway first.
    # If it doesn't return an empty route pool for AF.
    if not is_af_routable(af, netifaces):
        log("> af {} has no default route".format(af))
        return RoutePool([])

    # Hold results.
    results = []
    tasks = []

    # Copy route pool from Interface if it already exists.
    # Otherwise schedule task to get list of routes.
    for iface in interface_list:
        log(f"Routes task += {af} {skip_resolve} {netifaces}")
        tasks.append(
            get_routes(iface, af, skip_resolve, netifaces=netifaces)
        )

    # Tasks that need to be run.
    # Cmbine with results -- if any.
    link_locals = []
    if len(tasks):
        ret_lists = await asyncio.gather(*tasks)
        for ret_list in ret_lists:
            if len(ret_list) != 2:
                continue

            results = results + ret_list[0]
            link_locals = link_locals + ret_list[1]

    # Wrap all routes in a RoutePool and return the result.
    return RoutePool(results, link_locals)

# Combine all routes from interface into RoutePool.
def interfaces_to_rp(interface_list):
    rp = {}
    for af in VALID_AFS:
        route_lists = []
        for iface in interface_list:
            if af not in iface.rp:
                continue

            route_lists.append(
                copy.deepcopy(iface.rp[af].routes)
            )

        routes = sum(route_lists, [])
        rp[af] = RoutePool(routes)

    return rp

# Converts a Bind object to a Route.
# Interface for bind object may be None if it's loopback.
async def bind_to_route(bind_obj):
    if not isinstance(bind_obj, Bind):
        raise Exception("Invalid obj type passed to bind_to_route.")

    """
    nic_bind = 1 -- ipv4 nic or ipv6 link local
    ext_bind = 2 -- ipv4 external wan ip / ipv6 global ip
        black hole ip if called with no ips start_local

    ips = both set to ips value
    nic_bind or ext_bind based on dest address in sock_factory
    """
    assert(bind_obj.resolved)
    interface = bind_obj.interface
    nic_bind = ext_bind = bind_obj._bind_tups[0]
    af = bind_obj.af
    assert(interface.resolved)

    """
    If the ext_bind contains a valid public address then
    use this directly for the ext_ipr in the Route obj.
    Otherwise attempt to find a pre-existing route in
    the Interface route pool that has the same nic_bind
    and use it's associated ext_ipr.
    """
    ext_set = 0
    nic_ipr = IPRange(nic_bind)
    ext_ipr = IPRange(ext_bind)
    if not ext_ipr.is_public:
        if interface is not None:
            # Check all routes for a matching NIC IPR.
            for hey_route in interface.rp[af].routes:
                # Check all NIC IPRs.
                for nic_hey in hey_route.nic_ips:
                    # NIC IPR found in the route entries.
                    # Use the routes EXT.
                    if nic_ipr in nic_hey:
                        ext_ipr = hey_route.ext_ips[0]
                        ext_ipr = copy.deepcopy(ext_ipr)
                        ext_set = 1
                        break

                if ext_set:
                    break

    # Build route object.
    route = Route(
        af=af,
        nic_ips=[nic_ipr],
        ext_ips=[ext_ipr],
        interface=interface,
        ext_check=0
    )

    # Bind to port in route.
    await route.bind(port=bind_obj.bind_port)
    return route

if __name__ == "__main__": # pragma: no cover
    from .interface import Interface

    async def test_get_routes(): # pragma: no cover
        internode_iface = Interface("enp3s0")
        starlink_iface = Interface("wlp2s0")
        iface_list = [internode_iface, starlink_iface]
        """
        af = IP4
        rp = await Routes(iface_list, af)
        r1 = rp.routes[0]
        nr1, _ = ~r1

        # Should compare two routes WAN portions.
        assert(r1 != nr1)
        assert(r1 == r1)

        r_list = r1 != [r1]
        assert(r_list[0][0] != r1)
        """

        # Test no WAN route.
        af = IP6
        rp = await Routes(iface_list, af)
        r1 = rp.routes[0]

        # When resolving a route that isnt supported = slow
        # any way to get it to return faster?

        return

        ra, rb = rp.routes
        for r in rp.routes:
            print(r)
            print(r.nic_ips)
            print(r.ext_ips)

        ref_route_a = rp[0]
        print(rp.routes)

        print(ref_route_a)
        return

        ipr = IPRange("192.168.0.0", "255.255.255.0")
        r = RoutePool([ipr])
        #ipr2 = copy.deepcopy(ipr)

        print(id(ipr.ip))
        print(id(r.routes[0].ip))

        return
        routes = await get_routes(iface, IP4)
        print(routes)
        route = routes[0]
        print(route.nic_ips)
        print(route.ext_ips)

    async_test(test_get_routes)


