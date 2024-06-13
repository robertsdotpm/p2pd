"""
Without magic cookie = 3489 mode
    - cips / ports / change requests
With magic cookie = RFC 5389 >= mode
    - no change requests

the gen stun code needs to be updated to reflect this 


"""

import re

# Stun2 down

from .utils import *
from .net import *
from .address import Address
from .interface import Interface
from .base_stream import pipe_open
from .stun_utils import *

def stun_proto(buf, af):
    # Initialize a list of dict keys with None.
    fields = ["resp", "rip", "rport", "sip", "sport", "cip", "cport"]
    ret = {} and [ret.setdefault(field, None) for field in fields]

    # Check buffer is min length to avoid overflows.
    if len(buf) < 20:
        log("Invalid buf len in main STUN res.")
        return

    # Only support certain message type.
    msgtype = buf[0:2]
    if msgtype != b"\1\1":
        log("> STUN unknown msg type %s" % (to_hs(msgtype)))
        return

    # Extract length of message attributes.
    len_message = int(to_h(buf[2:4]), 16)
    len_remain = len_message

    # Avoid overflowing buffer.
    if len(buf) - 20 < len_message:
        log("> Invalid message length recv for stun reply.")
        return

    # Start processing message attributes.
    log("> stun parsing bind = %d" % len_remain)
    base = 20
    ret['resp'] = True
    while len_remain > 0:
        # Avoid overflow for attribute parsing.
        if base + 4 >= len(buf):
            log("> new attr field overflow")
            break

        # Extract attributes from message buffer.
        attr_type = buf[base:(base + 2)]
        attr_len = int(to_h(buf[(base + 2):(base + 4)]), 16)

        # Avoid attribute overflows.
        if attr_len <= 0:
            log("> STUN attr len")
            break
        if attr_len + base + 4 > len(buf):
            log("> attr len overflow")
            break

        # Log attribute type.
        log("> STUN found attribute type = %s" % (to_hs(attr_type)))

        # Your remote IP and reply port. The important part.
        if attr_type == b'\0\1':
            ip, port = extract_addr(buf, af, base)
            ret['rip'] = ip
            ret['rport'] = port
            log(f"set mapped address {ip}:{port}")

        # Address that the STUN server would send change reqs from.
        if attr_type == b'\0\5':
            ip, port = extract_addr(buf, af, base)
            ret['cip'] = ip
            ret['cport'] = port
            log(f"set ChangedAddress {ip}:{port}")

        base = base + 4 + attr_len
        len_remain -= (4 + attr_len)

    return ret


class STUNClientRef():
    def __init__(self, dest, proto=UDP, conf=NET_CONF):
        self.dest = dest
        self.interface = self.dest.route.interface
        self.af = self.dest.af
        self.proto = proto
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

if __name__ == "__main__":
    async def test_stun_client():
        i = await Interface().start_local()
        a = await Address("stunserver.stunprotocol.org", 3478, i.route(IP4))
        s = STUNClientRef(a)
        r = await s.get_all_attrs()

    async_test(test_stun_client)



