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
        return PeerHandle(name)


def derive_default_pnp_name(nic_ids, listen_port):
    """sha256(NIC list + listen port), truncated.  Same inputs → same
    name → same keystore file → stable identity across runs."""
    parts = sorted(str(x) for x in nic_ids if x)
    parts.append(str(listen_port))
    payload = ":".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


class Gate(object):
    """Async-context wrapper around a Node with keystore-managed identity."""

    def __init__(self, name=None, ifs=None, ip=None, port=None,
                 stop_rw=None, conf=None, sys_clock=None):
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
            nic_ids = [getattr(nic, "id", None) for nic in self.node.ifs]
            self.node.pnp_name = derive_default_pnp_name(nic_ids, self.node.listen_port)
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
        entry = getattr(self.node, "keystore_entry", None) if self.node else None
        if entry is None or not entry.tld:
            return None
        return entry.pnp_name + entry.tld

    @property
    def nickname_error(self):
        """The exception raised by the in-flight nickname registration
        task, or None on success / not yet attempted.  Callers use
        this to render typed errors (PnpServerResourceLimit,
        NameAlreadyRegistered, PnpServerUnreachable, FullNameFailure)
        instead of a generic "didn't register" message."""
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
        """Resolve a PeerHandle (or accept addr_bytes) and open a pipe."""
        if isinstance(target, PeerHandle):
            addr_bytes = await self._resolve(target.name)
        else:
            addr_bytes = target
        from .node.auto_connect import auto_connect
        return await auto_connect(
            self.node, addr_bytes, protocol=transport, timeout=timeout,
        )

    async def listen(self, handler):
        """Block accepting inbound peers, dispatching each new peer to
        ``handler(pipe)`` as a background task.  ``pipe`` is a
        per-peer wrapper exposing ``async for msg in pipe`` and
        ``await pipe.send(msg)``; for UDP the wrapper bakes in the
        peer's client_tup so the user code never sees it.
        """
        peers = {}

        async def shim(msg, client_tup, raw_pipe):
            if getattr(raw_pipe, "proto", None) == TCP:
                key = id(raw_pipe)
                ctup = None
            else:
                key = (id(raw_pipe), client_tup)
                ctup = client_tup
            wrapper = peers.get(key)
            if wrapper is None:
                wrapper = HandlerPipe(raw_pipe, ctup)
                peers[key] = wrapper
                asyncio.ensure_future(handler(wrapper))
            await wrapper.queue.put(msg)

        self.node.add_msg_cb(shim)
        await self.closed.wait()


class HandlerPipe(object):
    """Per-peer wrapper exposing async iteration + send.

    For TCP, ``client_tup`` is None and ``send(msg)`` calls the raw
    pipe's send directly (the connection knows its destination).  For
    UDP, ``client_tup`` is baked in so ``send(msg)`` dispatches the
    datagram back to the same peer.
    """

    def __init__(self, raw_pipe, client_tup=None):
        self.raw = raw_pipe
        self.client_tup = client_tup
        self.queue = asyncio.Queue()
        self.closed = False

    async def send(self, msg):
        if self.client_tup is None:
            await self.raw.send(msg)
        else:
            await self.raw.send(msg, self.client_tup)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.closed:
            raise StopAsyncIteration
        msg = await self.queue.get()
        if msg is None:
            raise StopAsyncIteration
        return msg

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        self.closed = True
        # TCP wrappers own the underlying socket lifetime; UDP wrappers
        # share one bound socket across many peers, so closing the
        # raw pipe per-peer would tear down everyone else's session.
        if self.client_tup is None:
            try:
                await self.raw.close()
            except (OSError, asyncio.TimeoutError):
                pass
        return False
