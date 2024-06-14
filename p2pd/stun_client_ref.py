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

import re

# Stun2 down

from .utils import *
from .net import *
from .address import Address
from .interface import Interface
from .base_stream import pipe_open
from .stun_defs import *
from .stun_utils import *




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
        pipe = await pipe_open(self.proto, route, self.dest)
        return pipe
    
    async def get_all_attrs(self, route=None):
        # Open con to STUN server.
        route = await self.get_route(route)
        pipe = await self.get_dest_pipe(route)

        # Build the STUN message.
        msg = STUNMsg()
        msg.magic_cookie = b'\0\0\0\0'
        send_buf = msg.pack()

        # Subscribe to replies that match the req tran ID.
        sub = sub_stun_msg(msg.txn_id, self.dest.tup)
        pipe.subscribe(sub)

        # Send the req and get a matching reply.
        recv_buf = await send_recv_loop(pipe, send_buf, sub, self.conf)
        ret = stun_proto(recv_buf, self.dest.af)

        
        ret['sip'] = self.dest.tup[0]
        ret['sport'] = self.dest.tup[1]
        ret['lport'] = pipe.sock.getsockname()[1]
        ret['lip'] = pipe.sock.getsockname()[0]
        print(ret)
        return ret, pipe


    async def get_wan_ip(self, route=None):
        route = await self.get_route(route)

    async def get_mapping(self, route=None):
        route = await self.get_route(route)



    async def test_stun_client():
        """
        Xport ^ txid = port
        """
        buf = b''
        buf = b'\x01\x01\x000!4Q#\x95\xb2/\xb8@\xa5\xb9\x99[\xe9\xda\xbb\x00\x01\x00\x08\x00\x01\xe1&\x9f\xc4\xc1\xb7\x00\x04\x00\x08\x00\x01\r\x96Xc\xd3\xd8\x00\x05\x00\x08\x00\x01\r\x97Xc\xd3\xd3\x80 \x00\x08\x00\x01\xc0\x12\xbe\xf0\x90\x94'
        ret = stun_proto2(buf, IP4)
        print(ret)

        return



        i = await Interface().start_local()
        a = await Address("stunserver.stunprotocol.org", 3478, i.route(IP4))
        s = STUNClientRef(a)
        r = await s.get_all_attrs()

    async_test(test_stun_client)



