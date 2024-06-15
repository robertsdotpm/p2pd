"""
Without magic cookie = 3489 mode
    - cips / ports / change requests
With magic cookie = RFC 5389 >= mode
    - no change requests
"""

from .errors import *
from .utils import *
from .net import *
from .address import Address
from .base_stream import pipe_open, BaseProto
from .stun_defs import *
from .stun_utils import *
from .pattern_factory import *
from .settings import *
from .route_defs import Route


class STUNClient():
    def __init__(self, dest, proto=UDP, mode=RFC3489, conf=NET_CONF):
        self.dest = dest
        self.interface = self.dest.route.interface
        self.af = self.dest.af
        self.proto = proto
        self.mode = mode
        self.conf = conf

    # Boilerplate to get a pipe to the STUN server.
    async def _get_dest_pipe(self, unknown):
        # Already open pipe.
        if isinstance(unknown, BaseProto):
            return unknown

        # Open a new con to STUN server.
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
        return await pipe_open(
            self.proto,
            route,
            self.dest,
            conf=self.conf
        )
    
    # Returns a STUN reply based on how client was setup.
    async def get_stun_reply(self, pipe=None, attrs=[]):
        pipe = await self._get_dest_pipe(pipe)
        return await get_stun_reply(
            self.mode,
            self.dest, 
            pipe,
            attrs
        )
    
    # Use a different port for the reply.
    async def get_change_port_reply(self, ctup, pipe=None):
        # Sanity check against expectations.
        if self.mode != RFC3489:
            error = "STUN change port only supported in RFC3480 mode."
            raise ErrorFeatureDeprecated(error)

        # Expect a reply from this address.
        reply_addr = await Address(
            # The IP stays the same.
            self.dest.tup[0],

            # But expect the reply on the change port.
            ctup[1],

            # Use a route from the same interface as dest.
            self.interface.route(self.af)
        )

        # Flag to make the port change request.
        pipe = await self._get_dest_pipe(pipe)
        return await get_stun_reply(
            self.mode,
            reply_addr,
            pipe,
            [[STUNAttrs.ChangeRequest, b"\0\0\0\2"]]
        )

    # Use a different IP and port for the reply.
    async def get_change_tup_reply(self, ctup, pipe=None):
        # Sanity check against expectations.
        if self.mode != RFC3489:
            error = "STUN change port only supported in RFC3480 mode."
            raise ErrorFeatureDeprecated(error)

        # Expect a reply from this address.
        reply_addr = await Address(
            # The IP differs.
            ctup[0],

            # ... and so does the port.
            ctup[1],

            # Use a route from the same interface as dest.
            self.interface.route(self.af)
        )

        # Flag to make the tup change request.
        pipe = await self._get_dest_pipe(pipe)
        return await get_stun_reply(
            self.mode,
            reply_addr,
            pipe,
            [[STUNAttrs.ChangeRequest, b"\0\0\0\6"]]
        )

    # Return only your remote IP.
    async def get_wan_ip(self, pipe=None):
        pipe = await self._get_dest_pipe(pipe)
        reply = await get_stun_reply(
            self.mode,
            self.dest,
            pipe
        )

        await reply.pipe.close()
        if hasattr(reply, "rtup"):
            return reply.rtup[0]

    # Return information on your local + remote port.
    # The pipe is left open to be used with punch code.
    async def get_mapping(self, pipe=None):
        pipe = await self._get_dest_pipe(pipe)
        reply = await get_stun_reply(
            self.mode,
            self.dest,
            pipe
        )

        ltup = reply.pipe.getsockname()
        if hasattr(reply, "rtup"):
            return (ltup[1], reply.rtup[1], reply.pipe)

async def get_stun_clients(af, serv_list, interface, proto=UDP):
    class MockRoute:
        def __init__(self):
            self.af = af
            self.interface = interface

    mock_route = MockRoute()
    stun_clients = []
    for serv_info in serv_list:
        async def get_stun_client(serv_info):
            dest = await Address(
                serv_info["primary"]["ip"],
                serv_info["primary"]["port"],
                mock_route
            )
            return STUNClient(dest, proto=proto)
        
        stun_clients.append(get_stun_client(serv_info))

    return await asyncio.gather(*stun_clients)

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


    i = await Interface().start_local()
    a = await Address("stunserver.stunprotocol.org", 3478, i.route(IP4))
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
    i = await Interface().start_local()
    stun_clients = []
    tasks = []
    for n in range(0, 5):
        dest = await Address(
            STUND_SERVERS[af][n]["primary"]["ip"],
            STUND_SERVERS[af][n]["primary"]["port"],
            i.route(af)
        )
        stun_client = STUNClient(dest, proto=proto)
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

if __name__ == "__main__":
    async_test(test_con_stun_client)



