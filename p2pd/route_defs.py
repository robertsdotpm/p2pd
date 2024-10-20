import copy
import ipaddress
import pprint
from functools import total_ordering
from .ip_range import *
from .netiface_extra import *
from .upnp import *
from .address import *

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
            desc=f"P2PD {hash(src_tup)}"[0:8],
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

"""
-- get stun clients
-- check if addr:
    - record all private ips
        - associate with the default ext
    - for pub ip
        - enable resolv:
            - check ext addr value
        - disable resolv:
            - accept as-is
-- get default route
-- sort all routes in order
-- ensure default route is first

cleanup:
    get_routes_with_res
    get_routes_without_res
        x get_stun_clients()
        x get_nic_iprs()
            ...
            x netiface_addr_to_ipr
        x task = get_default_route()


        sort_routes(default)







"""