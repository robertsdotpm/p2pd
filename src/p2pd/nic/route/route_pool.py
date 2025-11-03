import copy
from ...net.ip_range import *
from ..netifaces.netiface_extra import *
from ...protocol.upnp.upnp import *
from ...net.address import *
from ...net.bind.bind import *
from .route import Route

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

