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

Multi-bind: by default the server binds 127.0.0.1 (and a probed
127.0.0.2 alias when the platform allows it) plus ::1 when IPv6
loopback works.  Tests that want two clients to target *different*
loopback IPs of the same server -- e.g. simulating two TURN deployments --
get that for free without coordinating ports.

Usage:
    nic = await Interface()
    async with TURNServer(nic) as server:
        # server is running on 127.0.0.1 (+ 127.0.0.2 if available, + ::1)
        ...
"""

import asyncio
import os
import copy
import unittest
from struct import pack
from hashlib import md5

from aionetiface import *
from aionetiface.testing import probe_loopback_ips
from p2pd.traversal.plugins.turn.turn_defs import TURN_REFRESH_EXPIRY


# ──────────────────────────────────────────────────────────────
# Defaults
# ──────────────────────────────────────────────────────────────
TURN_TEST_PORT = 33478  # High port to avoid conflicts
TURN_TEST_REALM = b"test.local"
TURN_TEST_USER = b"testuser"
TURN_TEST_PASS = b"testpass"
TURN_RELAY_BASE = 34000  # Relay sockets start here


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
            self.id = getattr(real_nic, "id", 0)

        def route(self, req_af=None):
            r = copy.deepcopy(real_nic.route(af))
            # Replace nic_ips with just the target IP so bind_closure will
            # call self.interface.route(af).nic() -> target_ipr for binding.
            r.nic_ips = [target_ipr]
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

        def is_default(self, req_af=None, gws=None):
            return False

    _instance = FakeNIC()
    return _instance


def make_local_turn_server_entry(port=TURN_TEST_PORT, af=None, ip=None):
    """
    Build a get_infra-compatible dict pointing at the local test server.
    Keys match what get_turn_client() expects: ip, port, user, password.

    *ip* defaults to 127.0.0.1 / ::1 per *af* but may be overridden so
    tests that bind the server on a non-default loopback alias (e.g.
    127.0.0.2) can route their plugin through that alias.
    """
    if ip is None:
        ip = "::1" if (af == IP6) else "127.0.0.1"
    return {
        "ip": ip,
        "port": port,
        "user": to_s(TURN_TEST_USER),
        "password": to_s(TURN_TEST_PASS),
    }


def default_bind_ips():
    """
    Default per-AF bind IPs for the local test server.

    IPv4: 127.0.0.1 plus the next probed 127.0.0.x alias when one is
    available (Linux /8 always works, Windows usually does, macOS only
    has 127.0.0.1).  IPv6: ::1.

    Returned as a dict so callers can override one AF without losing
    the other defaults.
    """
    v4 = ["127.0.0.1"]
    for ip in probe_loopback_ips(max_count=4):
        if ip != "127.0.0.1" and ip not in v4:
            v4.append(ip)
            break
    return {IP4: v4, IP6: ["::1"]}


# ──────────────────────────────────────────────────────────────
# TURNServer
# ──────────────────────────────────────────────────────────────


class TURNServer:
    """
    Minimal local TURN server for unit / integration tests.

    Parameters
    ----------
    interface   : Interface   --  aionetiface NIC (for route objects)
    port        : int         --  control UDP port (default 0 = ephemeral)
    realm       : bytes
    user        : bytes       --  accepted username (auth is not HMAC-verified)
    pw          : bytes       --  password (stored but unused; for reference)
    relay_base  : int         --  first port number used for relay sockets
    bind_ip     : str or None --  legacy single-IP override.  When set,
                                  collapses bind_ips to {af: [bind_ip]}
                                  so older callers see the same behaviour.
    bind_ips    : dict or None --  per-AF list of IPs to bind on.  Defaults
                                  to default_bind_ips().  Each (af, ip) gets
                                  its own control socket and ephemeral port.
                                  Failed binds are logged and skipped; an AF
                                  is "started" if any of its IPs bound.
    """

    def __init__(
        self,
        interface,
        port=0,
        realm=TURN_TEST_REALM,
        user=TURN_TEST_USER,
        pw=TURN_TEST_PASS,
        relay_base=0,
        bind_ip=None,
        bind_ips=None,
    ):
        self.interface = interface
        self.port = port
        self.realm = realm
        self.user = user
        self.pw = pw
        self.bind_ip = bind_ip
        self.relay_base = relay_base

        if bind_ips is None:
            bind_ips = default_bind_ips()
        if bind_ip is not None:
            # Legacy single-IP override: collapse to one IP for whichever
            # AF that string belongs to.  Other AFs keep their defaults.
            af_for_ip = IP6 if ":" in bind_ip else IP4
            bind_ips = dict(bind_ips)
            bind_ips[af_for_ip] = [bind_ip]
        self.bind_ips = bind_ips

        # client_tup (tuple) -> allocation dict
        self.allocations = {}
        # (ip, port) -> allocation dict   (ip is the relay's bound IP)
        self.relay_map = {}
        # client_tup (tuple) -> nonce bytes
        self.nonces = {}

        # (af, ip) -> control Pipe
        self.control_pipes = {}
        # (af, ip) -> actual bound port
        self.bound_ports = {}
        # af -> port of the *first* successfully bound IP for that AF
        # (kept so existing single-IP callers still find a port).
        self.af_ports = {}

    # ── lifecycle ──────────────────────────────────────────────

    def started_afs(self):
        """Return the set of address families that bound at least one IP."""
        return set(af for (af, _) in self.control_pipes.keys())

    def started_ips(self, af):
        """Return the IPs successfully bound for *af* (in start order)."""
        out = []
        for (a, ip) in self.control_pipes.keys():
            if a == af:
                out.append(ip)
        return out

    def port_for(self, af, ip=None):
        """
        Port the server is listening on for (*af*, *ip*).

        When *ip* is None, returns the port of the first bound IP for *af*
        (matches the legacy af_ports[af] lookup).
        """
        if ip is None:
            return self.af_ports.get(af)
        return self.bound_ports.get((af, ip))

    async def start(self):
        """Bind one control socket per (AF, IP) combination."""
        for af in self.interface.supported():
            try:
                await self.start_af(af)
            except (OSError, ConnectionError):
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
            except (OSError, ConnectionError):
                pass

        for pipe in list(self.control_pipes.values()):
            try:
                await pipe.close()
            except (OSError, ConnectionError):
                pass

        self.allocations.clear()
        self.relay_map.clear()
        self.control_pipes.clear()
        self.bound_ports.clear()

    # ── per-AF setup ───────────────────────────────────────────

    async def start_af(self, af):
        """Bind one control socket per configured IP for *af*.

        Failures on individual IPs (e.g. 127.0.0.2 not aliased on macOS)
        log and continue.  If *every* IP for this AF fails the caller's
        outer try/except in start() swallows the OSError.
        """
        ips = self.bind_ips.get(af, [])
        bound_count = 0
        for ip in ips:
            try:
                await self.start_one(af, ip)
                bound_count += 1
            except (OSError, ConnectionError):
                log_exception()
        if bound_count == 0 and ips:
            raise OSError(
                "TURNServer: AF={0} could not bind any of {1}".format(af, ips)
            )

    async def start_one(self, af, ip):
        """Bind a single (AF, IP) control socket."""
        route = self.interface.route(af)
        await route.bind(ips=ip, port=0)

        async def cb(data, client_tup, pipe, bind_ip=ip):
            await async_wrap_errors(
                self.on_control(af, bind_ip, data, client_tup, pipe)
            )

        pipe = await Pipe(UDP, None, route).connect(cb)
        actual_port = route.bind_port
        self.control_pipes[(af, ip)] = pipe
        self.bound_ports[(af, ip)] = actual_port
        if af not in self.af_ports:
            self.af_ports[af] = actual_port
        if af == IP4 and not self.port:
            self.port = actual_port
        log(fstr(
            "TURNServer: AF={0} listening on {1}:{2}",
            (af, ip, actual_port),
        ))

    # ── relay socket allocation ────────────────────────────────

    async def open_relay(self, af, bind_ip, owner_tup, owner_pipe):
        """
        Open a new UDP relay socket.

        The relay binds on *bind_ip* -- the same loopback alias the
        client targeted -- so the XorRelayedAddress in the Allocate
        reply is reachable by anyone who can reach that alias.

        Returns the relay (ip, port) tuple and stores the allocation.
        The relay's msg_cb wraps received data in a DataIndication and
        forwards it to the allocation owner.
        """
        route = self.interface.route(af)
        await route.bind(ips=bind_ip, port=0)

        # Mutable reference so the closure can see the alloc after creation.
        holder = {}

        async def relay_cb(data, source_tup, relay_pipe):
            alloc = holder.get("a")
            if alloc is not None:
                await async_wrap_errors(self.forward(af, data, source_tup, alloc))

        relay_pipe = await Pipe(UDP, None, route).connect(relay_cb)
        relay_port = route.bind_port
        relay_tup = (bind_ip, relay_port)

        alloc = {
            "relay_tup": relay_tup,
            "relay_pipe": relay_pipe,
            "owner_tup": tuple(owner_tup),
            "owner_pipe": owner_pipe,  # control pipe (sends DataIndications)
            "permissions": set(),  # permitted peer IPs
            "af": af,
            "bind_ip": bind_ip,
        }
        holder["a"] = alloc
        self.allocations[tuple(owner_tup)] = alloc
        self.relay_map[(bind_ip, relay_port)] = alloc
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
            source_tup[0],
            source_tup[1],
            af,
            msg.txn_id,
            msg.magic_cookie,
            STUNAttrs.XorPeerAddress,
        )
        msg.write_attr(STUNAttrs.XorPeerAddress, peer_buf)
        msg.write_attr(STUNAttrs.Data, data)

        owner_pipe = alloc["owner_pipe"]
        owner_tup = alloc["owner_tup"]
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

    async def on_control(self, af, bind_ip, data, client_tup, pipe):
        try:
            msg, _ = STUNMsg.unpack(memoryview(data), mode=RFC5389)
        except (ValueError, IndexError):
            return
        if msg is None:
            return

        method = self.get_msg_method(msg)

        if method == STUNMsgTypes.Allocate:
            await self.handle_allocate(af, bind_ip, msg, method, client_tup, pipe)
        elif method == STUNMsgTypes.CreatePermission:
            await self.handle_create_permission(af, msg, method, client_tup, pipe)
        elif method == STUNMsgTypes.Refresh:
            await self.handle_refresh(af, msg, method, client_tup, pipe)

    # ── Allocate ───────────────────────────────────────────────

    async def handle_allocate(self, af, bind_ip, msg, method, client_tup, pipe):
        # First request (no credentials) -> challenge.
        if not self.has_credentials(msg):
            nonce = os.urandom(16)
            self.nonces[tuple(client_tup)] = nonce

            reply = self.make_reply(msg, method, STUNMsgCodes.ErrorResp)
            reply.write_attr(STUNAttrs.ErrorCode, error_attr(401, b"Unauthorized"))
            reply.write_attr(STUNAttrs.Realm, self.realm)
            reply.write_attr(STUNAttrs.Nonce, nonce)
            await pipe.send(reply.pack(), client_tup)
            return

        # Subsequent request (has credentials) -> allocate relay.
        alloc = self.allocations.get(tuple(client_tup))
        if alloc is None:
            relay_tup = await self.open_relay(af, bind_ip, client_tup, pipe)
        else:
            relay_tup = alloc["relay_tup"]

        reply = self.make_reply(msg, method, STUNMsgCodes.SuccessResp)

        # XorRelayedAddress
        relay_buf = encode_xor_addr(
            relay_tup[0],
            relay_tup[1],
            af,
            reply.txn_id,
            reply.magic_cookie,
            STUNAttrs.XorRelayedAddress,
        )
        reply.write_attr(STUNAttrs.XorRelayedAddress, relay_buf)

        # XorMappedAddress  (client's source IP:port as seen here)
        mapped_buf = encode_xor_addr(
            client_tup[0],
            client_tup[1],
            af,
            reply.txn_id,
            reply.magic_cookie,
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
