"""
Local STUN server for testing (RFC 3489 and RFC 5389).

Implements minimal STUN Binding Request/Response exchange over UDP and TCP:
  1. Client sends Binding Request
  2. Server responds with Binding Response containing:
     - XorMappedAddress: the client's source IP:port as seen by server
     - (optionally) ChangedAddress for RFC3489 mode

Auth and message integrity are not implemented.

Usage:
    nic = await Interface()
    async with STUNServer(nic) as server:
        # server is running on 127.0.0.1 (and ::1 if IPv6 available)
        ...
"""

import asyncio
import os
import copy
from struct import pack

from aionetiface import *
from aionetiface.net.net_defs import NET_CONF
from aionetiface.protocol.stun.stun_defs import (
    STUNMsg,
    STUNMsgTypes,
    STUNMsgCodes,
    STUNAttrs,
    STUNAddrTup,
    RFC3489,
    RFC5389,
    STUN_MAGIC_COOKIE,
)


STUN_TEST_PORT = 3478


def encode_stun_addr(ip, port, af, txid, magic_cookie, attr_code):
    addr = STUNAddrTup(
        ip=ip,
        port=port,
        af=af,
        txid=txid,
        magic_cookie=magic_cookie,
    )
    return addr.encode(attr_code)


class STUNServer:
    def __init__(self, interface, port=STUN_TEST_PORT, mode=RFC5389, bind_ip=None):
        self.interface = interface
        self.port = port
        self.mode = mode
        self.bind_ip = bind_ip
        self.control_pipes = {}

    def started_afs(self):
        """Return the set of address families the server successfully bound."""
        return set(af for (af, _proto) in self.control_pipes)

    async def start(self):
        for af in self.interface.supported():
            try:
                lo = self.loopback(af)
                route = self.interface.route(af)
                await route.bind(ips=lo, port=self.port)
                await self.start_af_udp(af, route)
                route2 = self.interface.route(af)
                await route2.bind(ips=lo, port=self.port)
                await self.start_af_tcp(af, route2)
            except Exception:
                log_exception()
        return self

    async def __aenter__(self):
        return await self.start()

    async def __aexit__(self, *_):
        await self.close()

    async def close(self):
        for pipe in list(self.control_pipes.values()):
            try:
                await pipe.close()
            except Exception:
                pass
        self.control_pipes.clear()

    def loopback(self, af):
        return self.bind_ip or ("::1" if af == IP6 else "127.0.0.1")

    async def start_af_udp(self, af, route):
        lo = self.loopback(af)

        async def cb(data, client_tup, pipe):
            await async_wrap_errors(self.on_binding_request(af, data, client_tup, pipe))

        pipe = await Pipe(UDP, None, route).connect(cb)
        self.control_pipes[(af, UDP)] = pipe
        log(fstr("STUNServer: AF={0} UDP listening on {1}:{2}", (af, lo, self.port)))

    async def start_af_tcp(self, af, route):
        lo = self.loopback(af)

        async def cb(data, client_tup, pipe):
            await async_wrap_errors(self.on_binding_request(af, data, client_tup, pipe))

        reuse_conf = {**NET_CONF, "reuse_addr": True}
        pipe = await Pipe(TCP, None, route, conf=reuse_conf).connect(cb)
        self.control_pipes[(af, TCP)] = pipe
        log(fstr("STUNServer: AF={0} TCP listening on {1}:{2}", (af, lo, self.port)))

    async def build_stun_reply(self, af, data, client_tup):
        try:
            msg, _ = STUNMsg.unpack(memoryview(data), mode=self.mode)
        except Exception:
            return None
        if msg is None:
            return None

        method = b_and(bytes(msg.msg_type), b"\x00\x0f")
        if method != STUNMsgTypes.Binding:
            return None

        reply = STUNMsg(
            msg_type=STUNMsgTypes.Binding,
            msg_code=STUNMsgCodes.SuccessResp,
            mode=self.mode,
        )
        reply.txn_id = bytes(msg.txn_id)

        mapped_buf = encode_stun_addr(
            client_tup[0],
            client_tup[1],
            af,
            reply.txn_id,
            reply.magic_cookie,
            STUNAttrs.XorMappedAddress,
        )
        reply.write_attr(STUNAttrs.XorMappedAddress, mapped_buf)
        return reply.pack()

    async def on_binding_request(self, af, data, client_tup, pipe):
        reply_data = await self.build_stun_reply(af, data, client_tup)
        if reply_data:
            await pipe.send(reply_data, client_tup)
