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
from functools import total_ordering
from .ip_range import *
from .netiface_extra import *
from .upnp import *

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

        # Maybe None for loopback interface.
        self.interface = interface
        self.route_pool = self.route_offset = self.host_offset = None

    async def forward(self, port=None, proto="TCP"):
        assert(self.resolved)
        port = port or self.bind_port
        ip = self.bind_ip(self.af)
        src_addr = await Address(ip, port).res(self.interface)
        return await port_forward(
            interface=self.interface,
            ext_port=port,
            src_addr=src_addr,
            desc=f"P2PD {hash(src_addr.tup)}"[0:8],
            proto=proto
        )

    async def rebind(self, port, ips=None):
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
        if self.af == IP6:
            for ipr in self.nic_ips:
                if ipr.is_private:
                    return ipr_norm(ipr)

            raise Exception("> Route.nic() with af=6 found no link-locals.")

        return ipr_norm(self.nic_ips[0])

    def ext(self):
        return ipr_norm(self.ext_ips[0])

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

    def _convert_other(self, other):
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
            assert(ipr.af == self.af)
            return ipr

        if isinstance(other, IPA_TYPES):
            af = v_to_af(other.version)
            assert(af == self.af)
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
        list_info =  [[nic_ips, self.nic_ips], [ext_ips, self.ext_ips]]
        for dest_list, src_list in list_info:
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
        s = "[NICs = {}, WAN = {}, AF = {}]".format(
            str(self.nic_ips),
            str(self.ext_ips),
            self.af
        )

        return s

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        other = self._convert_other(other)
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
        route.nic_bind = self.nic_bind
        route.ext_bind = self.ext_bind
        route._bind_tups = copy.deepcopy(self._bind_tups)
        route.resolved = self.resolved

        return route

class RoutePool():
    def __init__(self, routes=None):
        self.routes = routes or []

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
        wan_ip = IPRange(wan_ipr[rel_host_offset], cidr=CIDR_WAN)
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

    # Other important variables.
    stun_client = stun_client or STUNClient(interface, af=af)
    netifaces_af = af_to_netiface(af)
    if_addresses = netifaces.ifaddresses(nic_id)
    if netifaces_af in if_addresses:
        bound_addresses = if_addresses[netifaces_af]
        main_nics = []
        routes = []
        tasks = []
        for info in bound_addresses:
            nic_ipr = await netiface_addr_to_ipr(af, info, interface, loop, skip_bind_test)
            if nic_ipr is None:
                continue

            # All private IPs go to the same route.
            # The interface has one external WAN IP.
            if nic_ipr.is_private:
                main_nics.append(nic_ipr)
                continue
            else:
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
                async def ipr_is_public(nic_ipr, stun_client, main_nics):
                    # Use this IP for bind call.
                    src_ip = ip_norm(str(nic_ipr[0]))
                    local_addr = await Bind(
                        stun_client.interface,
                        af=stun_client.af,
                        port=0,
                        ips=src_ip
                    ).res()

                    # Get external IP and compare to bind IP.
                    wan_ip = await stun_client.get_wan_ip(
                        local_addr=local_addr,
                        conf=stun_conf
                    )

                    # Check if address is actually public.
                    if src_ip == wan_ip:
                        nic_ipr.is_private = False
                        nic_ipr.is_public = True
                        return Route(
                            af=af,
                            nic_ips=[nic_ipr],
                            ext_ips=[copy.deepcopy(nic_ipr)],
                            interface=stun_client.interface
                        )
                    else:
                        # In a 'public range' but used privately.
                        # Yes, this is silly but possible.
                        nic_ipr.is_private = True
                        nic_ipr.is_public = False
                        main_nics.append(nic_ipr)
    
                if skip_resolve == False:
                    # Determine if this address is really public.
                    tasks.append(
                        ipr_is_public(nic_ipr, stun_client, main_nics)
                    )
                    continue
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
                    continue

        # Process pending tasks.
        if len(tasks):
            results = await asyncio.gather(*tasks)
            results = strip_none(results)

            # Every discrete public IP or block is it's own route.
            [routes.append(route) for route in results]

        # Only bother to add a main route if it has NIC IPs assigned.
        if len(main_nics):
            if af == IP4:
                wan_ip = None
                if skip_resolve == False:
                    # Loop over main NICs.
                    # Discard all broken until WAN IP works.
                    # Then add all afterwards.
                    valid_main_nics = []
                    for n in range(0, len(main_nics)):
                        # Only do it until one works.
                        if wan_ip is None:
                            # Use this IP for bind call.
                            src_ip = ip_norm(str(main_nics[n][0]))
                            local_addr = await Bind(
                                stun_client.interface,
                                af=stun_client.af,
                                port=0,
                                ips=src_ip
                            ).res()

                            # Get external address for main interface.
                            ext_result = await stun_client.get_wan_ip(
                                local_addr=local_addr,
                                conf=stun_conf
                            )

                            # Save valid main NICs.
                            if ext_result is not None:
                                wan_ip = ext_result
                                valid_main_nics.append(main_nics[n])
                        else:
                            # Otherwise all NICs afterwards are added.
                            # Since route 1 will at least work.
                            valid_main_nics.append(main_nics[n])

                    # Trim main NICs based on what worked.
                    main_nics = valid_main_nics
                else:
                    # Will error bellow if no public NIC found.
                    wan_ip = str(main_nics[0][0])
                    for ipr in main_nics:
                        if ipr.is_public:
                            wan_ip = str(ipr[0])
                            break

                # All routes need a valid external address.
                # Check whether it was successful.
                if wan_ip is not None:
                    wan_ipr = IPRange(wan_ip, cidr=CIDR_WAN)
                    routes.append(
                        Route(
                            af=af,
                            nic_ips=main_nics,
                            ext_ips=[wan_ipr],
                            interface=interface
                        )
                    )
            else:
                # If it's v6 associate the link locals with
                # the global addresses.
                """
                In IPv6 binding to link local means you can only access
                other link local addresses. Same with global scope.
                That means that associating a list of private NIC
                addresses with the first available global scope IP
                might not make much sense. The IPv6-specific
                abstraction will associate the same list of link-local
                addresses with every separate, global-scope address
                so that the route pool code still works well to
                manage external addresses but link local nic bind
                code is still simple to achieve.
                """
                assert(isinstance(main_nics, list))
                for route in routes:
                    # Add link local IPs as routes NIC IPs.
                    # This will make the nic() code fast for IPv6.
                    route.nic_ips = main_nics

        return routes
    else:
        return []

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
        if af in iface.rp:
            results += sum(iface.rp[af].routes, [])
        else:
            tasks.append(
                async_wrap_errors(
                    get_routes(iface, af, skip_resolve, netifaces=netifaces)
                )
            )

    # Tasks that need to be run.
    # Cmbine with results -- if any.
    if len(tasks):
        list_of_route_lists = await asyncio.gather(*tasks)
        list_of_route_lists = strip_none(list_of_route_lists)
        results += sum(list_of_route_lists, [])

    # Wrap all routes in a RoutePool and return the result.
    return RoutePool(results)

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
    nic_bind = bind_obj._bind_tups[NIC_BIND][0]
    ext_bind = bind_obj._bind_tups[EXT_BIND][0]
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


