from ..utility.utils import *
from .net_utils import *
from .bind.bind_utils import *
from .ip_range import *

DNS_NAMESERVERS = {
    IP4: [
        # OpenDNS.
        "208.67.222.222",
        "208.67.220.220",
    ],
    IP6: [
        # OpenDNS.
        "2620:119:35::35",
        "2620:119:53::53",
    ]
}

async def async_res_domain_af(af, host):
    # Throw error if not installed.
    # So auto fallback to getaddrinfo.
    import aiodns

    # Get IP of domain based on specific address family.
    nameservers = DNS_NAMESERVERS[af]
    resolver = aiodns.DNSResolver(nameservers=nameservers)
    if af == IP4:
        query_type = "A"
    else:
        query_type = "AAAA"

    # On success use first returned result.
    results = await resolver.query(host, query_type)
    if len(results):
        result = results[0]
        ip = ip_norm(result.host)
        return (af, ip)
    
async def async_res_domain(host, route=None):
    # Make a list of DNS res tasks.
    tasks = []
    for af in VALID_AFS:
        tasks.append(
            async_res_domain_af(af, host)
        )

    # Concurrently get IP fields from domain.
    return strip_none(
        await asyncio.gather(
            *tasks,
            return_exceptions=False
        )
    )

async def sock_res_domain(host, route=None):
    # Current event loop.
    loop = asyncio.get_event_loop()

    # Uses a process pool executor.
    # Caution needed here.
    addr_infos = await loop.getaddrinfo(
        host,
        None,
    )

    # Pull out IP4 and IP6 results.
    results = []
    for addr_info in addr_infos:
        for af in VALID_AFS:
            if af == addr_info[0]:
                ip = ip_norm(addr_info[4][0])
                result = (af, ip)
                results.append(result)

    return results

class DestTup():
    def __init__(self, af, ip, port, ipr):
        if ipr is None:
            raise KeyError("AF not found for address")
        
        self.af = af
        self.ip = ip
        self.port = port
        self.tup = (ip, port)
        self.ipr = ipr
        self.is_private = ipr.is_private
        self.is_public = ipr.is_public
        self.is_loopback = ipr.is_loopback
        self.resolved = True

    def supported(self):
        return [self.af]

class Address():
    def __init__(self, host, port, nic=None, conf=NET_CONF):
        self.host = host
        self.port = port
        self.nic = nic
        self.conf = conf
        self.IP6 = self.IP4 = None
        self.v6_ipr = self.v4_ipr = None
        self.resolved = False
    
    async def res(self, route=None, host=None):
        host = host or self.host
        try:
            # Ensure human-readable IPs aren't passed as binary.
            if isinstance(host, bytes):
                host = to_s(host)

            # If it can be parsed as an IP.
            # Then it's an IP.
            ipr = IPRange(host)
            ipr.is_loopback = False

            # Set route from NIC.
            if self.nic is not None:
                if route is None:
                    route = self.nic.route()

            # Used to patch IPv6 private IPs.
            if route is not None:
                nic_id = route.interface.id
            else:
                nic_id = None
        
            # Apply any needed IP patches.
            #ip = self.patch_ip(ipr_norm(ipr), ipr, nic_id)
            ip = patch_connect_ip(ipr.af, ipr_norm(ipr), nic_id, ipr)
            if ip in VALID_LOOPBACKS:
                ipr.is_loopback = True

            # What type of IP.
            if ipr.af == IP4:
                self.IP4 = ip
                self.v4_ipr = ipr
            if ipr.af == IP6:
                self.IP6 = ip
                self.v6_ipr = ipr
        except Exception:
            # Resolve domain to IP.
            try:
                # Uses a manual DNS req to resolve a domain.
                # Bypasses any DNS errors.
                results = await asyncio.wait_for(
                    async_res_domain(host, route),
                    self.conf["dns_timeout"]
                )

                # Ensure some IPs returned.
                if not len(results):
                    raise Exception("Using fallback DNS")
            except Exception:
                # If that fails -- fallback to getaddrinfo.
                results = await asyncio.wait_for(
                    sock_res_domain(host, route),
                    self.conf["dns_timeout"]
                )

                # Otherwise complete failure.
                if not len(results):
                    raise Exception("could not resolve addr.")

            # Save results in class field.
            for result in results:
                _, ip = result
                await self.res(route=route, host=ip)

        self.resolved = True
        return self

    def __await__(self):
        return self.res().__await__()

    def select_ip(self, af):
        if af == IP4:
            ip, ipr = self.IP4, self.v4_ipr
        if af == IP6:
            ip, ipr = self.IP6, self.v6_ipr

        return DestTup(af, ip, self.port, ipr)

async def resolv_dest(af, dest, nic):
    if isinstance(dest, DestTup):
        return dest.tup
    
    if isinstance(dest, tuple):
        try:
            # An IP -- already resolved.
            IPRange(dest[0], cidr=af_to_cidr(af))
            return dest
        except Exception:
            dest = await Address(*dest, nic)
    
    if isinstance(dest, Address):
        return dest.select_ip(af).tup

async def workstation():
    host = "google.com"
    addr = AddressRewrite(host, 80)

    
    await addr.res()


    #await addr.fallback_res_domain(host)

    print(addr.IP4)
    print(addr.IP6)
    print(addr)

#async_test(workstation)


