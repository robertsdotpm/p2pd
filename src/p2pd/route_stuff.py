"""
Given a list of ip strings and a list of nics:
    - create a new route table that consists only of those IPs
    - apply these tables in-place only for the NICs where those IPs belong

accepted inputs:
    - v4 WAN ip
        -> route with that WAN ip and the NIC ips to use it
        - limit wan ips to only the defined set of wan ips
    - v4 NIC ip
        -> route with only that nic ip and the wan ip it points to
    - v6 link-local
        - build a list of link locals for that nic
        - set all the wan ip routes to use that list
    - v6 wan ip
        -> route with ext as only that wan ip
            - if link-locals defined for that nic set only to that list
            - otherwise reuse existing link locals
        - limit wan ips to only the defined set of wan ips
"""

from p2pd import *

def find_intersect(list_a, list_b):
    for list_a_val in list_a:
        for list_b_val in list_b:
            if list_a_val == list_b_val:
                return list_a_val
            
def sort_iprs(ipr_list):
    # Sort by public / private.
    pub_iprs = []
    priv_iprs = []
    for ipr in ipr_list:
        if ipr.is_public:
            pub_iprs.append(ipr)

        if ipr.is_private:
            priv_iprs.append(ipr)

    return pub_iprs, priv_iprs

def v6_route_pool_from_ips(ipr_list, nic):
    # Sort by public / private.
    pub_iprs, priv_iprs = sort_iprs(ipr_list)

    # If no link-locals are defined use pre-existing.
    if not priv_iprs:
        priv_iprs = nic.rp[IP6][0].link_locals

    routes = []
    for route in nic.rp[IP6]:
        # If public exts are specified limit to only those routes.
        if pub_iprs:
            pub_ipr = find_intersect(pub_iprs, route.ext_ips)
            if not pub_ipr:
                continue

            ext_ips = [pub_ipr]
        else:
            ext_ips = route.ext_ips

        routes.append(Route(IP6, ext_ips, ext_ips, nic))

    # Set link-local list.
    for route in routes:
        route.set_link_locals(priv_iprs)

    return routes

def v4_route_pool_from_ips(ipr_list, nic):
    # Sort by public / private.
    pub_iprs, priv_iprs = sort_iprs(ipr_list)

    print("wan ipr = ", pub_iprs)
    print("nic iprs = ", priv_iprs)
    routes = []
    for route in nic.rp[IP4]:
        # Use pre-existing route as template.
        nic_ipr = find_intersect(priv_iprs, route.nic_ips)
        if not nic_ipr:
            continue

        # Select only a certain WAN if chosen.
        wan_ipr = find_intersect(pub_iprs, route.ext_ips)
        if wan_ipr:
            ext_ips = [wan_ipr]
        else:
            ext_ips = route.ext_ips

        routes.append(Route(IP4, [nic_ipr], ext_ips, nic))

    return routes

def route_pool_from_ips(ip_list, nic):
    # Classify IPs by version.
    ipr_list = {IP4: [], IP6: []}
    for ip in ip_list:
        ipr = IPR(ip)
        if ipr.af == IP4:
            ipr_list[IP4].append(ipr)
    
        if ipr.af == IP6:
            ipr_list[IP6].append(ipr)

    # AF-specific route pool funcs.
    get_route_pool_funcs = {
        IP4: v4_route_pool_from_ips,
        IP6: v6_route_pool_from_ips
    }

    # Return route pool based on version
    rp = {}
    for af in (IP4, IP6):
        # Get list of routes based on IPR inputs.
        routes = get_route_pool_funcs[af](ipr_list[af], nic)

        # If IPs were specified then use them.
        # Otherwise use the already existing route pool.
        if routes:
            rp[af] = RoutePool(routes)
        else:
            rp[af] = nic.rp[af]

    return rp

def sort_ips_by_nic(ip_list, nic_list):
    pass

async def workspace():
    ip_list = ["10.0.1.19", "fe80::20c:29ff:fe7d:6654", "2400:a842:d1b4:0000:be64:25a7:3536:e2c0", "fe80:0000:0000:0000:020c:29ff:fe7d:6653"]
    nic = await Interface()
    rp = route_pool_from_ips(ip_list, nic)
    print(rp[IP4].to_dict())
    print(rp[IP6].to_dict())
    print("here")
    pass

if __name__ == "__main__":
    async_run(workspace())