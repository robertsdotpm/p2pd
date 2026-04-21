"""
Local TURN server for testing (RFC 5766, UDP only).

Implements the minimal subset of TURN that TURNClient exercises:
  1. Allocate (unsigned)   -> 401 Unauthorized + Realm + Nonce
  2. Allocate (signed)     -> 200 Success + XorRelayedAddress + XorMappedAddress + Lifetime
  3. CreatePermission      -> 200 Success  (permission recorded for logging only)
  4. Refresh               -> 200 Success + Lifetime
  5. Data relay            -> data arriving on a relay UDP socket is wrapped in a
                             DataIndication and sent to the allocation owner

Auth is deliberately simplified: we require Username/Realm/Nonce attributes in
the second Allocate, but we do NOT verify the HMAC.  This keeps the server
self-contained and fast without needing the client's key material.

Usage:
    nic = await Interface()
    async with TURNServer(nic) as server:
        # server is running on 127.0.0.1 (and ::1 if IPv6 available)
        ...
"""

import asyncio
import os
import copy
from struct import pack
from hashlib import md5

from aionetiface import *
from p2pd.protocol.turn.turn_defs import TURN_REFRESH_EXPIRY


# ──────────────────────────────────────────────────────────────
# Defaults
# ──────────────────────────────────────────────────────────────
TURN_TEST_PORT  = 33478          # High port to avoid conflicts
TURN_TEST_REALM = b"test.local"
TURN_TEST_USER  = b"testuser"
TURN_TEST_PASS  = b"testpass"
TURN_RELAY_BASE = 34000          # Relay sockets start here


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

def error_attr(code, msg=b""):
    """Encode an ErrorCode attribute payload (RFC 5766 §14.8)."""
    return pack("!HBB", 0, code // 100, code % 100) + msg


def encode_xor_addr(ip, port, af, txid, magic_cookie, attr_code):
    """Encode an XOR-mapped/relayed/peer address attribute."""
    addr = STUNAddrTup(
        ip=ip,
        port=port,
        af=af,
        txid=txid,
        magic_cookie=magic_cookie,
    )
    return addr.encode(attr_code)


def make_fake_nic(real_nic, af, target_ipr):
    """
    Return a fake NIC wrapper that forces route binding to *target_ipr*.

    Useful for creating TURNClient instances that are bound to a specific
    local IP when the real Interface has multiple addresses.

    Parameters
    ----------
    real_nic   : Interface  --  the real NIC whose route metadata we copy
    af         : AddressFamily
    target_ipr : IPRange    --  specific NIC IP to bind to
    """
    class FakeNIC:
        __name__ = "FakeNIC"

        def __init__(self):
            self.name = real_nic.name
            self.id   = getattr(real_nic, "id", 0)

        def route(self, req_af=None):
            r = copy.deepcopy(real_nic.route(af))
            # Replace nic_ips with just the target IP so bind_closure will
            # call self.interface.route(af).nic() -> target_ipr for binding.
            r.nic_ips  = [target_ipr]
            r.resolved = False
            # Keep r.interface pointing to this FakeNIC so that:
            #   1. Pipe.__init__ can set self.nic = route.interface (non-None).
            #   2. bind_closure calls self.interface.route(af).nic() which
            #      returns target_ipr via our overridden route().
            r.interface = _instance
            r.bind = bind_closure(r, binder_async)
            return r

        def supported(self):
            return [af]

    _instance = FakeNIC()
    return _instance


def make_local_turn_server_entry(port=TURN_TEST_PORT, af=None):
    """
    Build a get_infra-compatible dict pointing at the local test server.
    Keys match what get_turn_client() expects: ip, port, user, password.
    """
    ip4 = "127.0.0.1"
    ip6 = "::1"
    ip = ip6 if (af == IP6) else ip4
    return {
        "ip":       ip,
        "port":     port,
        "user":     to_s(TURN_TEST_USER),
        "password": to_s(TURN_TEST_PASS),
    }


# ──────────────────────────────────────────────────────────────
# TURNServer
# ──────────────────────────────────────────────────────────────

class TURNServer:
    """
    Minimal local TURN server for unit / integration tests.

    Parameters
    ----------
    interface   : Interface   --  aionetiface NIC (for route objects)
    port        : int         --  control UDP port (default 33478)
    realm       : bytes
    user        : bytes       --  accepted username (auth is not HMAC-verified)
    pw          : bytes       --  password (stored but unused; for reference)
    relay_base  : int         --  first port number used for relay sockets
    bind_ip     : str or None --  override the IP the server binds to;
                                  None -> loopback per AF (127.0.0.1 / ::1)
    """

    def __init__(
        self,
        interface,
        port=TURN_TEST_PORT,
        realm=TURN_TEST_REALM,
        user=TURN_TEST_USER,
        pw=TURN_TEST_PASS,
        relay_base=TURN_RELAY_BASE,
        bind_ip=None,
    ):
        self.interface  = interface
        self.port       = port
        self.realm      = realm
        self.user       = user
        self.pw         = pw
        self.bind_ip    = bind_ip
        self.relay_base = relay_base

        # client_tup (tuple) -> allocation dict
        self.allocations = {}
        # relay_port (int)   -> allocation dict
        self.relay_map   = {}
        # client_tup (tuple) -> nonce bytes
        self.nonces      = {}

        # af -> control Pipe
        self.control_pipes = {}

        self._next_relay_port = relay_base

    # ── lifecycle ──────────────────────────────────────────────

    async def start(self):
        """Bind one control socket per supported address family."""
        for af in self.interface.supported():
            try:
                await self.start_af(af)
            except Exception:
                log_exception()
        return self

    async def __aenter__(self):
        return await self.start()

    async def __aexit__(self, *_):
        await self.close()

    async def close(self):
        """Tear down all relay and control sockets."""
        for alloc in list(self.relay_map.values()):
            try:
                await alloc["relay_pipe"].close()
            except Exception:
                pass

        for pipe in list(self.control_pipes.values()):
            try:
                await pipe.close()
            except Exception:
                pass

        self.allocations.clear()
        self.relay_map.clear()
        self.control_pipes.clear()

    # ── per-AF setup ───────────────────────────────────────────

    def loopback(self, af):
        return self.bind_ip or ("::1" if af == IP6 else "127.0.0.1")

    async def start_af(self, af):
        lo = self.loopback(af)
        route = self.interface.route(af)
        await route.bind(ips=lo, port=self.port)

        async def cb(data, client_tup, pipe):
            await async_wrap_errors(
                self.on_control(af, data, client_tup, pipe)
            )

        pipe = await Pipe(UDP, None, route).connect(cb)
        self.control_pipes[af] = pipe
        log(fstr("TURNServer: AF={0} listening on {1}:{2}", (af, lo, self.port)))

    # ── relay socket allocation ────────────────────────────────

    async def open_relay(self, af, owner_tup, owner_pipe):
        """
        Open a new UDP relay socket.

        Returns the relay (ip, port) tuple and stores the allocation.
        The relay's msg_cb wraps received data in a DataIndication and
        forwards it to the allocation owner.
        """
        lo = self.loopback(af)
        relay_port = self._next_relay_port
        self._next_relay_port += 1

        route = self.interface.route(af)
        await route.bind(ips=lo, port=relay_port)

        # Mutable reference so the closure can see the alloc after creation.
        holder = {}

        async def relay_cb(data, source_tup, _relay_pipe):
            alloc = holder.get("a")
            if alloc is not None:
                await async_wrap_errors(
                    self.forward(af, data, source_tup, alloc)
                )

        relay_pipe = await Pipe(UDP, None, route).connect(relay_cb)
        relay_tup  = (lo, relay_port)

        alloc = {
            "relay_tup":  relay_tup,
            "relay_pipe": relay_pipe,
            "owner_tup":  tuple(owner_tup),
            "owner_pipe": owner_pipe,   # control pipe (sends DataIndications)
            "permissions": set(),       # permitted peer IPs
            "af": af,
        }
        holder["a"] = alloc
        self.allocations[tuple(owner_tup)] = alloc
        self.relay_map[relay_port]         = alloc
        return relay_tup

    # ── relay data -> DataIndication ───────────────────────────

    async def forward(self, af, data, source_tup, alloc):
        """
        Wrap raw relay data in a DataIndication and send it to the owner.

        The XorPeerAddress is set to *source_tup* -- the address of whoever
        sent data to the relay port (e.g. the other client's control socket).
        This matches what TURNClient.process_replies() expects.
        """
        msg = STUNMsg(
            msg_type=STUNMsgTypes.Data,
            msg_code=STUNMsgCodes.Indication,
            mode=RFC5389,
        )

        peer_buf = encode_xor_addr(
            source_tup[0], source_tup[1], af,
            msg.txn_id, msg.magic_cookie,
            STUNAttrs.XorPeerAddress,
        )
        msg.write_attr(STUNAttrs.XorPeerAddress, peer_buf)
        msg.write_attr(STUNAttrs.Data, data)

        owner_pipe = alloc["owner_pipe"]
        owner_tup  = alloc["owner_tup"]
        await owner_pipe.send(msg.pack(), owner_tup)

    # ── control message dispatch ───────────────────────────────

    @staticmethod
    def get_msg_method(msg):
        return b_and(bytes(msg.msg_type), b"\x00\x0f")

    def make_reply(self, request, method_bytes, msg_code):
        """Create a reply with the request's TXID."""
        r = STUNMsg(msg_type=method_bytes, msg_code=msg_code, mode=RFC5389)
        r.txn_id = bytes(request.txn_id)
        return r

    def has_credentials(self, msg):
        """Return True if msg contains Username + Realm + Nonce attrs."""
        flags = {"u": False, "r": False, "n": False}
        saved = msg.attr_cursor
        msg.attr_cursor = 0
        while not msg.eof():
            code, _, _ = msg.read_attr()
            if code is None:
                break
            c = bytes(code)
            if c == STUNAttrs.Username:
                flags["u"] = True
            elif c == STUNAttrs.Realm:
                flags["r"] = True
            elif c == STUNAttrs.Nonce:
                flags["n"] = True
        msg.attr_cursor = saved
        return all(flags.values())

    async def on_control(self, af, data, client_tup, pipe):
        try:
            msg, _ = STUNMsg.unpack(memoryview(data), mode=RFC5389)
        except Exception:
            return
        if msg is None:
            return

        method = self.get_msg_method(msg)

        if method == STUNMsgTypes.Allocate:
            await self.handle_allocate(af, msg, method, client_tup, pipe)
        elif method == STUNMsgTypes.CreatePermission:
            await self.handle_create_permission(af, msg, method, client_tup, pipe)
        elif method == STUNMsgTypes.Refresh:
            await self.handle_refresh(af, msg, method, client_tup, pipe)

    # ── Allocate ───────────────────────────────────────────────

    async def handle_allocate(self, af, msg, method, client_tup, pipe):
        # First request (no credentials) -> challenge.
        if not self.has_credentials(msg):
            nonce = os.urandom(16)
            self.nonces[tuple(client_tup)] = nonce

            reply = self.make_reply(msg, method, STUNMsgCodes.ErrorResp)
            reply.write_attr(STUNAttrs.ErrorCode,
                             error_attr(401, b"Unauthorized"))
            reply.write_attr(STUNAttrs.Realm, self.realm)
            reply.write_attr(STUNAttrs.Nonce, nonce)
            await pipe.send(reply.pack(), client_tup)
            return

        # Subsequent request (has credentials) -> allocate relay.
        alloc = self.allocations.get(tuple(client_tup))
        if alloc is None:
            relay_tup = await self.open_relay(af, client_tup, pipe)
        else:
            relay_tup = alloc["relay_tup"]

        reply = self.make_reply(msg, method, STUNMsgCodes.SuccessResp)

        # XorRelayedAddress
        relay_buf = encode_xor_addr(
            relay_tup[0], relay_tup[1], af,
            reply.txn_id, reply.magic_cookie,
            STUNAttrs.XorRelayedAddress,
        )
        reply.write_attr(STUNAttrs.XorRelayedAddress, relay_buf)

        # XorMappedAddress  (client's source IP:port as seen here)
        mapped_buf = encode_xor_addr(
            client_tup[0], client_tup[1], af,
            reply.txn_id, reply.magic_cookie,
            STUNAttrs.XorMappedAddress,
        )
        reply.write_attr(STUNAttrs.XorMappedAddress, mapped_buf)

        # Lifetime
        reply.write_attr(STUNAttrs.Lifetime, pack("!I", TURN_REFRESH_EXPIRY))

        await pipe.send(reply.pack(), client_tup)

    # ── CreatePermission ───────────────────────────────────────

    async def handle_create_permission(self, af, msg, method, client_tup, pipe):
        alloc = self.allocations.get(tuple(client_tup))
        if alloc is not None:
            # Record permitted peer IPs.
            msg.attr_cursor = 0
            while not msg.eof():
                code, _, data = msg.read_attr()
                if code is None:
                    break
                if bytes(code) == STUNAttrs.XorPeerAddress:
                    peer = STUNAddrTup(
                        af=af,
                        txid=msg.txn_id,
                        magic_cookie=msg.magic_cookie,
                    )
                    peer.decode(code, data)
                    alloc["permissions"].add(peer.tup[0])

        reply = self.make_reply(msg, method, STUNMsgCodes.SuccessResp)
        await pipe.send(reply.pack(), client_tup)

    # ── Refresh ────────────────────────────────────────────────

    async def handle_refresh(self, af, msg, method, client_tup, pipe):
        reply = self.make_reply(msg, method, STUNMsgCodes.SuccessResp)
        reply.write_attr(STUNAttrs.Lifetime, pack("!I", TURN_REFRESH_EXPIRY))
        await pipe.send(reply.pack(), client_tup)
