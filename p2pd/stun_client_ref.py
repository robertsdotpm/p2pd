"""
Without magic cookie = 3489 mode
    - cips / ports / change requests
With magic cookie = RFC 5389 >= mode
    - no change requests

the gen stun code needs to be updated to reflect this 

    msgtype = buf[0:2]
    if msgtype != b"\1\1":
    
prob needs different logic if 8489 is selected
like the bit mask stuff

what about attributes?

-- look for xor mapped address todo:

... and insert a MAPPED-ADDRESS attribute instead of an XOR-
   MAPPED-ADDRESS attribute.
    - make sure to support this xor mapped attribute
"""

from .errors import *
from .utils import *
from .net import *
from .address import Address
from .interface import Interface
from .base_stream import pipe_open
from .stun_defs import *
from .stun_utils import *
from .route import Route

class STUNClientRef():
    def __init__(self, dest, proto=UDP, mode=RFC3489, conf=NET_CONF):
        self.dest = dest
        self.interface = self.dest.route.interface
        self.af = self.dest.af
        self.proto = proto
        self.mode = mode
        self.conf = conf

    async def get_route(self, route):
        if route is None:
            route = await self.interface.route(self.af).bind()

        return route
    
    async def get_dest_pipe(self, route):
        return await pipe_open(
            self.proto,
            route,
            self.dest,
            conf=self.conf
        )
    
    # Handles making a STUN request to a server.
    # Pipe also accepts route and its upgraded to a pipe.
    async def get_stun_reply(self, reply_addr=None, pipe=None, attrs=[]):
        """
        The function uses subscriptions to the TXID so that even
        on unordered protocols like UDP the right reply is returned.
        The reply address forms part of that pattern which is an
        elegant way to validate responses from change requests
        which will otherwise timeout on incorrect addresses.
        """
        if reply_addr is None:
            reply_addr = self.dest

        # Open con to STUN server.
        if pipe is None or isinstance(pipe, Route):
            route = await self.get_route(pipe)
            pipe = await self.get_dest_pipe(route)
            if pipe is None:
                raise ErrorPipeOpen("STUN pipe open failed.")

        # Build the STUN message.
        msg = STUNMsg(mode=self.mode)
        for attr in attrs:
            attr_code, attr_data = attr
            msg.write_attr(attr_code, attr_data)

        # Subscribe to replies that match the req tran ID.
        sub = sub_to_stun_reply(msg.txn_id, reply_addr.tup)
        pipe.subscribe(sub)

        # Send the req and get a matching reply.
        send_buf = msg.pack()
        recv_buf = await send_recv_loop(pipe, send_buf, sub, self.conf)
        if recv_buf is None:
            raise ErrorNoReply("STUN recv loop got no reply.")

        # Return response.
        reply, _ = stun_proto(recv_buf, self.dest.af)
        reply.pipe = pipe
        return reply
    
    # Use a different port for the reply.
    async def get_change_port_reply(self, ctup, pipe=None):
        attr = [
            STUNAttrs.ChangeRequest,
            b"\0\0\0\2"
        ]

        reply_addr = await Address(
            # The IP stays the same.
            self.dest.tup[0],

            # But expect the reply on the change port.
            ctup[1],

            # Use a route from the same interface as dest.
            self.interface.route(self.af)
        )

        return await self.get_stun_reply(
            reply_addr,
            pipe,
            [attr]
        )

    # Use a different IP and port for the reply.
    async def get_change_tup_reply(self, ctup, pipe=None):
        attr = [
            STUNAttrs.ChangeRequest,
            b"\0\0\0\6"
        ]

        reply_addr = await Address(
            # The IP differs.
            ctup[0],

            # ... and so does the port.
            ctup[1],

            # Use a route from the same interface as dest.
            self.interface.route(self.af)
        )

        return await self.get_stun_reply(
            reply_addr,
            pipe,
            [attr]
        )

    # Return only your remote IP.
    async def get_wan_ip(self, pipe=None):
        reply = await self.get_stun_reply(self.dest, pipe)
        await reply.pipe.close()
        if hasattr(reply, "rtup"):
            return reply.rtup[0]

    # Return information on your local + remote port.
    # The pipe is left open to be used with punch code.
    async def get_mapping(self, pipe=None):
        reply = await self.get_stun_reply(self.dest, pipe)
        ltup = reply.pipe.getsockname()
        if hasattr(reply, "rtup"):
            return (ltup[1], reply.rtup[1], reply.pipe)


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



    i = await Interface().start_local()
    a = await Address("stunserver.stunprotocol.org", 3478, i.route(IP4))
    s = STUNClientRef(a)
    r = await s.get_stun_reply()
    print(r.rtup)
    print(r.ctup)
    print(r.pipe.sock)


    c1 = await s.get_change_port_reply(r.ctup)
    print("change port reply = ")
    print(c1)
    print(c1.rtup)
    print(c1.ctup)

    c1 = await s.get_change_tup_reply(r.ctup)
    print("change tup reply = ")
    print(c1)
    print(c1.rtup)
    print(c1.ctup)

    await r.pipe.close()

async_test(test_stun_client)



