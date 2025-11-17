import asyncio
from ...net.ip_range import *
from ..netifaces.netiface_extra import *
from ...protocol.upnp.upnp import *
from ...net.address import *
from .route_pool import *
from ...utility.pattern_factory import *
from ...settings import *
from .route_utils import *
from ...net.bind.bind import *

"""
Loads external IP associated with a nic IP.
Give a single address for a NIC (may appear public or private) --
use STUN to lookup what WAN address ends up being reported after using
that particular address for a bind() call.
"""
async def lookup_wan_ip_for_nic_ip(src_ip, min_agree, stun_clients, timeout):
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
            timeout,
            wait_all=True
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
    except Exception:
        log_exception()

"""
Network interface cards have a list of addresses to bind on them. 
They consist of one or more ranges of IPs. A range may have one IP in it.
Depending on the gateway and route tables -- binding to any of those IPs
ends up with a certain public address from another machines perspective on
the Internet. To discover that perspective -- STUN is used.

However, since public STUN servers are used a portion of them may be adversarial
(or simply misconfigured to return bad results.) So this function allows for
public addresses to be discovered assuming that a minimum number of STUN
servers report the same result. It is optimized so that if there are ranges
of IPs for a NIC (with a million IPs for example) -- it only checks the
first address to learn an associated IP and then generalized the result.

Servers often like to directly set public addresses for their NIC cards
to indicate that they're directly connected to the Internet without NATs
or any of that junk. In that case -- the software still checks if these are
valid addresses because a machine is free to set whatever addresses they like
for their interface but it doesn't mean that the addresses are valid.
"""
async def discover_nic_wan_ips(af, min_agree, enable_default, interface, stun_clients, netifaces, timeout):
    # Get a list of tasks to resolve NIC addresses.
    tasks = []
    link_locals = []
    priv_iprs = []
    nic_iprs = await get_nic_iprs(af, interface, netifaces)
    for nic_ipr in nic_iprs:
        assert(int(nic_ipr[0]))
        if ip_norm(nic_ipr[0])[:2] in ["fe", "fd"]:
            link_locals.append(nic_ipr)
            log(fstr("Addr is link local so skipping"))
            continue

        if nic_ipr.is_private:
            priv_iprs.append(nic_ipr)
            continue
        else:
            src_ip = ip_norm(str(nic_ipr[0]))
            tasks.append(
                to_task(
                    async_wrap_errors(
                        lookup_wan_ip_for_nic_ip(
                            src_ip,
                            min_agree,
                            stun_clients,
                            timeout
                        )
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
            to_task(
                async_wrap_errors(
                    lookup_wan_ip_for_nic_ip(
                        af_default_nic_ip,
                        min_agree,
                        stun_clients,
                        timeout
                    )
                )
            )
        )

    # Append task to get route using priv nic.
    """
    Optimization:
    If there was only one private NIC IPR and enable default already ran.
    It's already done the necessary work to resolve that first route.
    So only run the code bellow if there's more than 1 or enable default
    has been disabled.

    > 1 or (len(priv_iprs) and not enable_default)
    """
    priv_src = ""
    if len(priv_iprs) > 1 or (len(priv_iprs) and not enable_default):
        priv_src = ip_norm(str(priv_iprs[0]))
        tasks.append(
            to_task(
                async_wrap_errors(
                    lookup_wan_ip_for_nic_ip(
                        priv_src,
                        min_agree,
                        stun_clients,
                        timeout
                    )
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
            log(fstr("Route error {0} disabling default route.", (af,)))
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

