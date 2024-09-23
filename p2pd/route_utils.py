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

import asyncio
import copy
from functools import cmp_to_key
from .ip_range import *
from .netiface_extra import *
from .upnp import *
from .address import *
from .route_defs import *
from .pattern_factory import *
from .settings import *

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

async def get_nic_iprs(af, interface, netifaces):
    tasks = []
    netifaces_af = af_to_netiface(af)
    if_addresses = netifaces.ifaddresses(interface.name)
    if netifaces_af in if_addresses:
        bound_addresses = if_addresses[netifaces_af]
        for info in bound_addresses:
            # Only because it calls getaddrinfo is it async.
            task = netiface_addr_to_ipr(
                af,
                interface.id,
                info
            )

            tasks.append(task)

    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]

async def get_wan_ip_cfab(src_ip, min_agree, stun_clients, timeout):
    try:
        tasks = []
        interface = stun_clients[0].interface
        af = stun_clients[0].af
        for stun_client in stun_clients:
            local_addr = await Bind(
                stun_client.interface,
                af=stun_client.af,
                port=0,
                ips=src_ip
            ).res()

            # Get external IP and compare to bind IP.
            task = async_wrap_errors(
                stun_client.get_wan_ip(
                    # Will be upgraded to a pipe.
                    pipe=local_addr
                )
            )
            tasks.append(task)

        wan_ip = await concurrent_first_agree_or_best(
            min_agree,
            tasks,
            timeout
        )

        if wan_ip is None:
            return None
        
        # Convert default details to a Route object.
        cidr = af_to_cidr(af)
        ext_ipr = IPRange(wan_ip, cidr=cidr)
        nic_ipr = IPRange(src_ip, cidr=cidr)
        if nic_ipr.is_private or src_ip != wan_ip:
            nic_ipr.is_private = True
            nic_ipr.is_public = False
        else:
            nic_ipr.is_private = False
            nic_ipr.is_public = True


        return (src_ip, Route(af, [nic_ipr], [ext_ipr], interface))
    except:
        log_exception()

def sort_routes(routes):
    # Deterministically order routes list.
    cmp = lambda r1, r2: int(r1.ext_ips[0]) - int(r2.ext_ips[0])
    return sorted(routes, key=cmp_to_key(cmp))

def get_route_by_src(src_ip, results):
    route = [y for x, y in results if x == src_ip]
    if len(route):
        route = route[0]
    else:
        route = None

    return route

def exclude_routes_by_src(src_ips, results):
    new_list = []
    for src_ip, route in results:
        found_src = False
        for needle_ip in src_ips:
            if src_ip == needle_ip:
                found_src = True
        
        if not found_src:
            new_list.append(route)

    return new_list

async def get_routes_with_res(af, min_agree, enable_default, interface, stun_clients, netifaces, timeout):
    # Get a list of tasks to resolve NIC addresses.
    tasks = []
    link_locals = []
    priv_iprs = []
    nic_iprs = await get_nic_iprs(af, interface, netifaces)
    for nic_ipr in nic_iprs:
        assert(int(nic_ipr[0]))
        if ip_norm(nic_ipr[0])[:2] in ["fe", "fd"]:
            link_locals.append(nic_ipr)
            log(f"Addr is link local so skipping")
            continue

        if nic_ipr.is_private:
            priv_iprs.append(nic_ipr)
            continue
        else:
            src_ip = ip_norm(str(nic_ipr[0]))
            tasks.append(
                async_wrap_errors(
                    get_wan_ip_cfab(
                        src_ip,
                        min_agree,
                        stun_clients,
                        timeout
                    )
                )
            )

    # Append task for get default route.
    cidr = af_to_cidr(af)
    af_default_nic_ip = ""
    if enable_default:
        dest = "8.8.8.8" if af == IP4 else "2001:4860:4860::8888"
        af_default_nic_ip = determine_if_path(af, dest)
        tasks.append(
            async_wrap_errors(
                get_wan_ip_cfab(
                    af_default_nic_ip,
                    min_agree,
                    stun_clients,
                    timeout
                )
            )
        )

    # Append task to get route using priv nic.
    priv_src = ""
    if len(priv_iprs):
        priv_src = ip_norm(str(priv_iprs[0]))
        tasks.append(
            async_wrap_errors(
                get_wan_ip_cfab(
                    priv_src,
                    min_agree,
                    stun_clients,
                    timeout
                )
            )
        )

    # Resolve interface addresses CFAB.
    results = await asyncio.gather(*tasks)
    results = [r for r in results if r is not None]

    # Only the default NIC will have
    # a default route enabled for the af.
    if enable_default:
        default_route = get_route_by_src(
            af_default_nic_ip,
            results
        )

        """
        If the main NIC IP for the default interface for AF
        is not in the NIC IPs for this interface then
        don't enable the use of the default route.
        """
        af_default_nic_ipr = IPRange(af_default_nic_ip, cidr=cidr)
        if af_default_nic_ipr not in nic_iprs:
            default_route = None
            log(f"Route error {af} disabling default route.")
    else:
        default_route = None

    # Load route used for priv nics.
    priv_route = get_route_by_src(priv_src, results)

    # Exclude priv_route and default.
    exclude = [priv_src, af_default_nic_ip]
    routes = exclude_routes_by_src(exclude, results)

    # Add a single route for all private IPs (if exists)
    # Use default routes external address (if exists)
    if len(priv_iprs):
        priv_ext = None
        if default_route is not None:
            priv_ext = default_route.ext_ips
        else:
            if priv_route is not None:
                priv_ext = priv_route.ext_ips

        if priv_ext is not None:
            priv_route = Route(af, priv_iprs, priv_ext, interface)
            routes.append(priv_route)

    # Only use default route if no other option.
    if not len(routes):
        if default_route is None:
            routes = []
        else:
            routes = [default_route]
    else:
        # Deterministic order = consistent for servers.
        routes = sort_routes(routes)

    # Set link locals in route list.
    [r.set_link_locals(link_locals) for r in routes]

    # Return results back to caller.
    return [af, routes, link_locals]

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


