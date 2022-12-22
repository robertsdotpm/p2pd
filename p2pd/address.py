import asyncio
import socket
import ipaddress
from .net import *

# TODO: address doesn't support domain resolution
# from a specific interface. This may not matter though.
class Address():
    def __init__(self, host, port, sock_type=socket.SOCK_STREAM, sock_timeout=1):
        self.sock_timeout = sock_timeout
        self.resolved = False
        self.sock_type = sock_type
        self.host = host
        self.host_type = None
        self.port = int(port)
        self.afs_found = [] # Supported AFs once resolved.
        self.ips = {} # Destination indexed by IP.
        self.host = to_s(host) if host is not None else host
        log("> Address: %s:%d" % (self.host, self.port))

    async def res(self, route):
        # Lookup IPs for domain.
        loop = asyncio.get_event_loop()

        # Determine if IP or domain.
        self.chosen = AF_ANY
        if self.host is None:
            return

        # Try parse host as an IP address.
        self.af = route.af
        try:
            self.ip_obj = ipaddress.ip_address(self.host)
            if self.ip_obj.version == 4:
                if self.af not in [AF_ANY, IP4]:
                    raise Exception("Found IP doesn't match AF.")

                self.chosen = socket.AF_INET
                self.ips[AF_ANY] = self.ips[socket.AF_INET] = self.host
            else:
                if self.af not in [AF_ANY, IP6]:
                    raise Exception("Found IP doesn't match AF.")

                self.chosen = socket.AF_INET6
                self.ips[AF_ANY] = self.ips[socket.AF_INET6] = self.host

            self.host_type = HOST_TYPE_IP
        except Exception as e:
            self.ip_obj = None
            self.host_type = HOST_TYPE_DOMAIN
            self.chosen = self.af

        # Set IP port tup.
        self.as_tup = self.tup = self.tuple = ()

        # Set target to resolve.
        if self.host_type == HOST_TYPE_IP:
            # Target is an IP.
            target = self.ips[self.chosen]

            # Patch link local addresses.
            if self.af == IP6 and target not in ["::", "::1"]:
                target = ip6_patch_bind_ip(
                    self.ip_obj,
                    target,
                    route.interface
                )
        else:
            # Target is a domain name.
            target = self.host

        # Get endpoint connect / bind results.
        results = []
        afs_wanted = VALID_AFS if self.chosen == AF_ANY else [self.chosen]
        family = 0 if len(afs_wanted) == 2 else afs_wanted[0]
        try:
            addr_infos = loop.getaddrinfo(
                target,
                self.port,
                type=self.sock_type,
                family=family
            )
            results = await asyncio.wait_for(addr_infos, self.sock_timeout)
        except Exception as e:
            log(f"{target} {self.port} {family} {self.sock_type}")
            log_exception()
            log("> Address: res e = %s" % (str(e)))

        # Choose a tuple that matches requirements.
        addr_tup = None
        afs_found = []  
        for addr_info in results:
            for af in afs_wanted:
                if af == addr_info[0]:
                    addr_tup = addr_info[4]
                    if af not in afs_found:
                        afs_found.append(af)

        # No results found for our requirements.
        if addr_tup is None:
            log("> Address: res couldnt find compatible address")
            self.chosen = AF_NONE
            raise Exception("couldnt translate address")
        else:
            self.as_tup = self.tup = self.tuple = addr_tup

        # Set attributes of the IP like if private or loopback.
        self.ip_set_info(addr_tup[0])
        self.afs_found = afs_found
        self.resolved = True
        return self

    def supported(self):
        return self.afs_found

    def ip_set_info(self, ip_s):
        # Determine whether IP is public or private.
        ip_obj = ip_f(ip_s)
        if ip_obj.is_private:
            self.is_private = True
            self.is_public = False
        else:
            self.is_private = False
            self.is_public = True

        # Used for IPv6 code.
        if str(ip_obj) in VALID_LOOPBACKS:
            self.is_loopback = True
        else:
            self.is_loopback = False

    def target(self):
        return self.tup[0]

    def as_tuple(self):
        return self.as_tup

    def __hash__(self):
        return hash(repr(self))

    def  __len__(self):
        return 0

async def test_address(): # pragma: no cover
    iface = Interface("enp3s0")
    start = timestamp()
    a = await Address("www.google.com", 80).res(iface.route())
    end = timestamp() - start

if __name__ == "__main__": # pragma: no cover
    from .interface import Interface
    from .net import IP6
    from .utils import timestamp, async_test
    async_test(test_address)
