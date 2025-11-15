"""
Without magic cookie = 3489 mode
    - cips / ports / change requests
With magic cookie = RFC 5389 >= mode
    - no change requests

Original stun code was based on https://github.com/talkiq/pystun3 but through trial-and-error I found that this
code incorrectly handles magic cookies, xor encoding,
and has many other issues.

The current code is based on extensive modifications to the TURN proxy code found in this repo: https://github.com/trichimtrich/turnproxy which includes a very good
parser for STUN messages. I've merged in logic from
talkiqs fork and my bug fixes for NAT detection.

changes:
- full async support
- add more stun servers
- test that they all work
- improve error checking
- add ipv6 support
- improve commenting
- fix some smol bugs (including nat test bugs)
- load balancing to avoid overloading
- result average support to avoid invalid servers
- separate list of hosts that support ipv6 for less failures on ipv6
- TCP support (for get mappings)
- delta n test (some nats have predictable mappings and assign then a delta apart)
- added better checking for 'change IPs' and made a new address family for hosts that return correct change ip responses. the nat determination code needs to use these hosts. for regular 'get wan ip' and 'get port mapped' lookups you can use the change hosts or the mapping hosts (larger list)
- proper support for RFC 3489 and RFC 5389 >=

Note 1: Some of the response times for DNS lookups to the STUN servers in
this module are on the order of 1 second or higher -- an astronomical
amount of time for a network. I have tried to use concurrency patterns
where ever possible to avoid delaying other, faster lookups.4

Note 2: I've read the STUN RFC and it seems to indicate that many of the fields in the protocol format take place over byte boundaries. Yet the client code here works on all the servers I've tested it on and doesn't make these assumptions. It's possible the spec is wrong or maybe my code just won't work with particular features of the STUN protocol. No idea.

TODO: sort the hosts by how fast they respond to a STUN request from domain resolution to reply time.
TODO: It seems that this is a pattern that reoccurs in several functions.
The general form might also make sense to add to the Net module.
TODO: Refactor code. The code in this module offers many good features but the code reflects too much cruft. It could do with a good cleanup.
"""

from ...errors import *
from ...utility.utils import *
from ...net.net_utils import *
from ...net.address import Address
from ...net.pipe.pipe import *
from .stun_defs import *
from .stun_utils import *
from ...utility.pattern_factory import *
from ...settings import *
from ...nic.route.route import Route
from ...net.bind.bind import *


class STUNClient():
    def __init__(self, af, dest, nic, proto=UDP, mode=RFC3489, conf=NET_CONF):
        self.dest = dest
        self.interface = nic
        self.af = af
        self.proto = proto
        self.mode = mode
        self.conf = conf

    # Boilerplate to get a pipe to the STUN server.
    async def _get_dest_pipe(self, unknown):
        # Already open pipe.
        if isinstance(unknown, Pipe):
            return unknown

        # Open a new con to STUN server.
        route = unknown
        if unknown is None:
            route = self.interface.route(self.af)
            await route.bind()

        # Route passed in already bound.
        # Upgrade it to a pipe.
        if isinstance(unknown, Route):
            route = unknown
        if isinstance(unknown, Bind):
            route = unknown

        # Otherwise use details to make a new pipe.
        self.dest = await resolv_dest(self.af, self.dest, self.interface)
        return await Pipe(self.proto, self.dest, route, conf=self.conf).connect()
    
    # Returns a STUN reply based on how client was setup.
    async def get_stun_reply(self, pipe=None, attrs=[]):
        pipe = await self._get_dest_pipe(pipe)
        return await get_stun_reply(
            self.mode,
            self.dest,
            self.dest, 
            pipe,
            attrs
        )
    
    # Use a different port for the reply.
    async def get_change_port_reply(self, ctup, pipe=None):
        """
        With RFC 5389 the change request feature was deprecated.
        Servers aren't required to support it and I've yet to see any that do.
        """
        # Sanity check against expectations.
        if self.mode != RFC3489:
            error = "STUN change port only supported in RFC3489 mode."
            raise ErrorFeatureDeprecated(error)

        # Expect a reply from this address.
        reply_addr = (
            # The IP stays the same.
            self.dest[0],

            # But expect the reply on the change port.
            ctup[1],
        )

        # Flag to make the port change request.
        pipe = await self._get_dest_pipe(pipe)
        return await get_stun_reply(
            self.mode,
            self.dest,
            reply_addr,
            pipe,
            [[STUNAttrs.ChangeRequest, b"\0\0\0\2"]]
        )

    # Use a different IP and port for the reply.
    async def get_change_tup_reply(self, ctup, pipe=None):
        # Sanity check against expectations.
        if self.mode != RFC3489:
            error = "STUN change port only supported in RFC3489 mode."
            raise ErrorFeatureDeprecated(error)

        # Flag to make the tup change request.
        pipe = await self._get_dest_pipe(pipe)
        return await get_stun_reply(
            self.mode,
            self.dest,
            ctup,
            pipe,
            [[STUNAttrs.ChangeRequest, b"\0\0\0\6"]]
        )

    # Return only your remote IP.
    async def get_wan_ip(self, pipe=None):
        pipe = await self._get_dest_pipe(pipe)
        try:
            reply = await get_stun_reply(
                self.mode,
                self.dest,
                self.dest,
                pipe
            )

            if hasattr(reply, "rtup"):
                return ip_norm(reply.rtup[0])
        finally:
            if pipe is not None:
                await pipe.close()

    # Return information on your local + remote port.
    # The pipe is left open to be used with punch code.
    # NOTE: Pipe doesn't get closed from this. Intentional?
    async def get_mapping(self, pipe=None):
        pipe = await self._get_dest_pipe(pipe)
        reply = await get_stun_reply(
            self.mode,
            self.dest,
            self.dest,
            pipe
        )

        ltup = reply.pipe.sock.getsockname()
        if hasattr(reply, "rtup"):
            return (ltup[1], reply.rtup[1], reply.pipe)

async def get_stun_clients(af, max_agree, interface, proto=UDP, servs=None, conf=NET_CONF):
    class MockRoute:
        def __init__(self):
            self.af = af
            self.interface = interface

    # Copy random STUN servers to use.
    if servs is None:
        if proto == UDP:
            stun_servs = STUN_CHANGE_SERVERS[proto][af]
        else:
            stun_servs = STUN_MAP_SERVERS[proto][af]
        
        serv_list = list_clone_rand(stun_servs, max_agree)
    else:
        serv_list = servs

    mock_route = MockRoute()
    stun_clients = []
    for serv_info in serv_list:
        async def get_stun_client(serv_info):
            dest = (
                serv_info["primary"]["ip"],
                serv_info["primary"]["port"],
            )
            return STUNClient(
                af,
                dest,
                interface,
                proto=proto,
                mode=serv_info["mode"],
                conf=conf,
            )
        
        stun_clients.append(get_stun_client(serv_info))
        if len(stun_clients) >= max_agree:
            break

    return await asyncio.gather(*stun_clients)

async def get_n_stun_clients(af, n, interface, proto=UDP, limit=5, conf=NET_CONF):
    # Find a working random STUN server.
    # Limit to 5 attempts.
    async def worker():
        for _ in range(0, limit):
            try:
                stun = (await get_stun_clients(
                        af=af,
                        max_agree=1,
                        interface=interface,
                        proto=proto,
                        conf=conf,
                    ))[0]

                out = await stun.get_mapping()
                if out is not None:
                    return stun
            except asyncio.CancelledError:
                raise
            except Exception:
                log_exception()
                continue
            
    # Create list of worker tasks for concurrency (faster.)
    tasks = []
    for _ in range(0, n):
        tasks.append(
            async_wrap_errors(
                worker()
            )
        )

    # Run tasks and return results.
    return strip_none(
        await asyncio.gather(
            *tasks,
            return_exceptions=True,
        )
    )

async def test_stun_client():
    """
    Xport ^ txid = port
    """

    """
    buf = b''
    buf = b'\x01\x01\x000!4Q#\x95\xb2/\xb8@\xa5\xb9\x99[\xe9\xda\xbb\x00\x01\x00\x08\x00\x01\xe1&\x9f\xc4\xc1\xb7\x00\x04\x00\x08\x00\x01\r\x96Xc\xd3\xd8\x00\x05\x00\x08\x00\x01\r\x97Xc\xd3\xd3\x80 \x00\x08\x00\x01\xc0\x12\xbe\xf0\x90\x94'
    ret = stun_proto(buf, IP4)
    print(ret)

    return

    """
    from .interface import Interface


    i = await Interface()
    a = ("stunserver.stunprotocol.org", 3478)
    s = STUNClientRef(a)
    r = await s.get_stun_reply()
    print(r.rtup)
    print(r.stup)
    print(r.ctup)
    print(r.pipe.sock)


    c1 = await s.get_change_port_reply(r.ctup)
    print("change port reply = ")
    print(c1)
    print(c1.rtup)
    print(c1.stup)

    c1 = await s.get_change_tup_reply(r.ctup)
    print("change tup reply = ")
    print(c1)
    print(c1.rtup)
    print(c1.stup)

    await r.pipe.close()


async def test_con_stun_client():
    from .interface import Interface
    af = IP4; proto = UDP;
    i = await Interface()
    stun_clients = []
    tasks = []
    for n in range(0, 5):
        dest = (
            STUND_SERVERS[af][n]["primary"]["ip"],
            STUND_SERVERS[af][n]["primary"]["port"],
        )
        stun_client = STUNClient(dest, i, proto=proto)
        stun_clients.append(stun_client)
        task = stun_client.get_wan_ip()
        tasks.append(task)

    min_agree = 2
    out = await concurrent_first_agree_or_best(
        min_agree,
        tasks,
        timeout=2
    )


    print(out)

    await asyncio.sleep(2)




if __name__ == "__main__":
    pass
    #async_test(change_server_bind_experiment)



