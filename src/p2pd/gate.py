"""High-level entry point for p2pd.

    async with Gate("alice") as gate:
        link = await gate.connect(peer.find("bob"))
        async with link:
            async for msg in link:
                await link.send(msg)

Gate wraps a Node: it derives or accepts a PNP name, loads or creates
the matching priv key from the JSON keystore at
``~/aionetiface/<pnp_name>.json``, registers (or refreshes) the name
on every PNP server, and exposes connect / listen.

``Gate("foo")`` uses the explicit name "foo".  ``Gate()`` derives a
deterministic per-host name from the NIC list + listen port, so two
runs on the same host with the same NIC selection share an identity
while different hosts get distinct identities without coordination.
"""
from typing import Any, Awaitable, Callable, Optional
import asyncio
import hashlib

from aionetiface import TCP

from .node.node import Node
from .node.node_start import load_network_interfaces, load_machine_identity


class PeerHandle(object):
    """Opaque token returned by ``peer.find(name)``.  Resolved to a
    real address by ``Gate.connect`` via the gate's Nickname client."""

    def __init__(self, name):
        self.name = name


class peer(object):
    """Namespace for peer-resolution helpers."""

    @staticmethod
    def find(name):
        # Auto-append the active PNP TLD when the caller passes a bare
        # nickname.  Lets `peer.find("alice")` Just Work alongside the
        # explicit `peer.find("alice.p2p")` form.  Resolution downstream
        # (resolve_pnp_addr) requires a TLD-suffixed name; without this
        # the bare-name case silently falls through as raw addr_bytes
        # and connect explodes on a malformed addr.
        from .node.nickname import pnp_name_has_tld, pnp_get_tld
        from aionetiface import IP4, PNP_SERVERS
        if not pnp_name_has_tld(name):
            tld = pnp_get_tld(list(range(len(PNP_SERVERS[IP4]))))
            name = name + tld
        return PeerHandle(name)


def derive_default_pnp_name(nic_macs, listen_port):
    """sha256(NIC MAC list + listen port), truncated.  Same inputs → same
    name → same keystore file → stable identity across runs.

    Keyed on MAC addresses so the derivation is unique per machine.
    Kernel ifindex (nic.id on Linux) is reproducible per machine but
    collides cross-machine (ifindex 2 = primary NIC on essentially
    every Linux box), which produced same-name collisions across
    unrelated hosts."""
    parts = sorted(str(x) for x in nic_macs if x)
    parts.append(str(listen_port))
    payload = ":".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


class Gate(object):
    """Async-context wrapper around a Node with keystore-managed identity."""

    def __init__(self, name=None, ifs=None, ip=None, port=0,
                 stop_rw=None, conf=None, sys_clock=None):
        # port=0 by default so two Gate instances on the same machine
        # (the canonical "run the echo listener, then run a connector
        # in another terminal" first-use pattern) don't collide on the
        # legacy 10001.  listen_on_ifs pre-resolves 0 to an OS-assigned
        # ephemeral port via a wildcard probe socket, then every NIC
        # bind targets that resolved port -- so the published addr,
        # loopback aliases, and nickname registration all stay
        # consistent with each other.  Pass an explicit port to pin one.
        self.requested_name = name
        self.node_kwargs = {
            "ifs": ifs,
            "ip": ip,
            "port": port,
            "stop_rw": stop_rw,
            "conf": conf,
        }
        self.sys_clock = sys_clock
        self.node = None
        self.closed = asyncio.Event()

    def add_msg_cb(self, cb):
        """Register a per-message callback before listen() is called.
        Pass-through to the underlying Node so callers can hook
        protocol handlers (e.g. echo) before start() runs."""
        if self.node is None:
            self.node = Node(**{k: v for k, v in self.node_kwargs.items() if v is not None})
        self.node.add_msg_cb(cb)

    async def __aenter__(self):
        if self.node is None:
            self.node = Node(**{k: v for k, v in self.node_kwargs.items() if v is not None})

        # Pin the PNP name BEFORE start() so node_start's keystore
        # lookup picks up our priv key (or generates a fresh one).
        # When the caller didn't pass a name, run the two cheap pre-
        # start phases that establish nic list + listen port, derive
        # the name from them, then continue normally.  Both phases are
        # idempotent (guards on node.ifs / node.listen_port) so the
        # subsequent node.start() re-running them is a no-op.
        if self.requested_name is None:
            await load_network_interfaces(self.node)
            await load_machine_identity(self.node)
            nic_macs = [getattr(nic, "mac", None) for nic in self.node.ifs]
            self.node.pnp_name = derive_default_pnp_name(nic_macs, self.node.listen_port)
        else:
            self.node.pnp_name = self.requested_name

        await self.node.start(sys_clock=self.sys_clock)

        # Wait for the in-flight nickname registration task so the
        # keystore entry (and therefore self.full_name) is populated
        # by the time __aenter__ returns.
        register_task = getattr(self.node, "nickname_register_task", None)
        if register_task is not None:
            try:
                await register_task
            except (OSError, asyncio.TimeoutError):
                pass

        return self

    @property
    def full_name(self):
        """Return ``<pnp_name><tld>`` (e.g. "alice.p2p") once
        registration has completed; returns None if registration was
        skipped or failed."""
        return getattr(self.node, "full_name", None) if self.node else None

    @property
    def nickname_error(self):
        """The exception raised by the in-flight nickname registration
        task, or None on success / not yet attempted.  Callers use
        this to render typed errors (PnpServerResourceLimit,
        PnpServerUnreachable, FullNameFailure) instead of a generic
        "didn't register" message."""
        return getattr(self.node, "nickname_error", None) if self.node else None

    async def __aexit__(self, exc_type, exc, tb):
        self.closed.set()
        if self.node is not None:
            try:
                await self.node.close()
            except (OSError, asyncio.TimeoutError):
                pass
        return False

    async def connect(self, target, transport=None, timeout=None):
        """Resolve a PeerHandle / nickname / addr_bytes and return a Link.

        ``target`` is one of:
        - a ``PeerHandle`` (returned by ``peer.find("name")``);
        - a ``<name>.<tld>`` nickname string;
        - raw addr_bytes from ``node.address()``.

        ``transport`` accepts ``"tcp"`` / ``"udp"`` (string) or the
        aionetiface ``TCP`` / ``UDP`` constants.  ``timeout`` (seconds)
        bounds the auto_connect race; on hit, ``connect`` returns
        ``None``.

        Returns a ``Link`` on success, or ``None`` on failure.
        """
        from aionetiface import TCP as _TCP, UDP as _UDP
        if isinstance(target, PeerHandle):
            dest = target.name
        else:
            dest = target

        proto = transport
        if isinstance(proto, str):
            proto = {"tcp": _TCP, "udp": _UDP}.get(proto.lower(), proto)

        from .node.auto_connect import auto_connect
        kwargs = {}
        if proto is not None:
            kwargs["protocol"] = proto
        coro = auto_connect(self.node, dest, **kwargs)
        if timeout is not None:
            try:
                pipe, _plugin = await asyncio.wait_for(coro, timeout=timeout)
            except asyncio.TimeoutError:
                return None
        else:
            pipe, _plugin = await coro
        if pipe is None:
            return None
        return Link(pipe)

    async def listen(self, handler):
        """Run forever, dispatching each inbound message to ``handler(link, msg)``.

        ``link`` is a per-peer ``Link`` wrapper; ``await link.send(msg)``
        replies on the same channel.  For UDP the link bakes in the
        peer's client_tup so the handler never sees it.

        ``handler`` is called as a background task per message, so a
        slow handler can't block dispatch on other peers.

        If the gate hasn't been entered (``async with``) yet, this
        starts it for the duration of the listen call.  Cancel the
        outer task or set ``gate.closed`` to stop.
        """
        owns_gate = False
        if self.node is None:
            await self.__aenter__()
            owns_gate = True

        peers = {}

        async def shim(msg, client_tup, raw_pipe):
            if getattr(raw_pipe, "proto", None) == TCP:
                key = id(raw_pipe)
                ctup = None
            else:
                key = (id(raw_pipe), client_tup)
                ctup = client_tup
            link = peers.get(key)
            if link is None:
                link = Link(raw_pipe, ctup)
                peers[key] = link
            asyncio.ensure_future(handler(link, msg))

        self.node.add_msg_cb(shim)
        try:
            await self.closed.wait()
        finally:
            if owns_gate:
                await self.__aexit__(None, None, None)


class Link(object):
    """Bidirectional peer link returned by ``Gate.connect`` and yielded
    by the ``Gate.listen`` handler shim.

    ``await link.send(msg)`` writes bytes to the peer.  ``async for msg
    in link`` iterates inbound bytes (only meaningful on the connector
    side; listener-side messages arrive via the handler arg).
    ``async with link`` closes the link on exit (TCP only — UDP server
    pipes are shared across many peers, so closing per-peer would tear
    down everyone else's session).
    """

    def __init__(self, pipe, client_tup=None):
        self.pipe = pipe
        self.client_tup = client_tup
        self.closed = False
        self._subscribed = False

    async def send(self, msg):
        if self.client_tup is None:
            await self.pipe.send(msg)
        else:
            await self.pipe.send(msg, self.client_tup)

    def _ensure_subscribed(self):
        if not self._subscribed:
            from aionetiface import SUB_ALL
            self.pipe.subscribe(SUB_ALL)
            self._subscribed = True

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.closed:
            raise StopAsyncIteration
        self._ensure_subscribed()
        from aionetiface import SUB_ALL
        msg = await self.pipe.recv(SUB_ALL)
        if msg is None or self.closed:
            raise StopAsyncIteration
        return msg

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        self.closed = True
        if self.client_tup is None:
            try:
                await self.pipe.close()
            except (OSError, asyncio.TimeoutError):
                pass
        return False
