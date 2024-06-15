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
from functools import cmp_to_key
from .ip_range import *
from .netiface_extra import *
from .upnp import *
from .address import *
from .route_defs import *
from .pattern_factory import *
from .stun_client import *

"""
As there's only one STUN server in the preview release the
consensus code is not needed.
"""
ROUTE_CONSENSUS = [1, 1]


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

async def get_nic_iprs(af, nic_id, netifaces):
    tasks = []
    netifaces_af = af_to_netiface(af)
    if_addresses = netifaces.ifaddresses(nic_id)
    if netifaces_af in if_addresses:
        bound_addresses = if_addresses[netifaces_af]
        for info in bound_addresses:
            # Only because it calls getaddrinfo is it async.
            task = netiface_addr_to_ipr(
                af,
                nic_id,
                info
            )

            tasks.append(task)

    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]

async def get_default_route(min_agree, stun_clients, timeout):
    tasks = []
    interface = stun_clients[0].interface
    for stun_client in stun_clients:
        af = stun_client.af
        route = stun_client.interface.route()
        await route.bind(
            ips=ANY_ADDR_LOOKUP[af],
            port=0
        )

        # Get external IP and compare to bind IP.
        task = stun_client.get_wan_ip(
            # Will be upgraded to a pipe.
            pipe=route
        )
        tasks.append(task)

    wan_ip = await concurrent_first_agree_or_best(
        min_agree,
        tasks,
        timeout
    )

    if wan_ip is not None:
        # Convert default details to a Route object.
        cidr = af_to_cidr(af)
        nic_ipr = IPRange(ANY_ADDR_LOOKUP[af], cidr=cidr)
        ext_ipr = IPRange(wan_ip, cidr=cidr)
        return ["default", Route(af, [nic_ipr], [ext_ipr], interface)]

async def get_routes_with_res(af, max_agree, interface, netifaces):
    # Copy random STUN servers to use.
    serv_list = STUND_SERVERS[af][:]
    random.shuffle(serv_list)
    serv_list = serv_list[:max_agree]

    # Used to resolve nic addresses.
    stun_clients = await get_stun_clients(af, serv_list, interface)
    nic_iprs = await get_nic_iprs(af, interface.id, netifaces)

    # Get a list of tasks to resolve NIC addresses.
    tasks = []
    link_locals = []
    priv_iprs = []
    for nic_ipr in nic_iprs:
        if ip_norm(nic_ipr[0])[:4] == "fe80":
            link_locals.append(nic_ipr)
            log(f"Addr is link local so skipping")
            continue

        if nic_ipr.is_private:
            priv_iprs.append(nic_ipr)
            continue
        else:
            pass

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


