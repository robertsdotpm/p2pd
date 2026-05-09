"""Traversal plugin for direct (non-NATed) connections.

Plain TCP connect from src["ip"] to dest["ip"]:dest["port"].

Routing decisions (which IP per route_type, v6 link-local %scope, loopback
alias selection) all live in the manager before run() fires.  By the time
this plugin runs, ``self.src["ip"]`` is the resolved local-bind IP,
``self.dest["ip"]`` / ``["port"]`` is the dial target, and ``self.nic``
is already the right Interface for binding (Interface("default") for
loopback IPs, the physical NIC otherwise).  Call ``self.bind()`` to get a
ready-to-use route.
"""
import asyncio
from aionetiface import TCP, Pipe, log, log_exception, fstr, to_b
from ...traversal_plugin import Plugin
from ...strategy_registry import register
from .con_id_frame import CON_ID_PREFIX


@register(phase="direct")
class DirectConnect(Plugin):
    """Open a plain TCP connection to the peer."""

    name = "direct_connect"
    transport = TCP

    async def run(self, reply=None):
        dest = (self.dest["ip"], self.dest["port"])
        try:
            route = await self.bind()
        except (OSError, ValueError):
            log_exception()
            self.result.set_result(None)
            return

        try:
            pipe = await asyncio.wait_for(
                Pipe(TCP, dest, route).connect(),
                timeout=4.0,
            )
        except (OSError, ConnectionError, asyncio.TimeoutError):
            log_exception()
            self.result.set_result(None)
            return

        if pipe is None or pipe.sock is None:
            self.result.set_result(None)
            return

        # In-band ConId frame: the very first bytes on the new TCP pipe
        # carry b"P2P-CID:<plugin_id>\n" so the responder's node_protocol
        # can resolve any reverse_connect inbound future for plugin_id
        # without a separate signal-channel round trip.
        try:
            await pipe.send(CON_ID_PREFIX + to_b(self.plugin_id) + b"\n")
        except (OSError, ConnectionError, asyncio.TimeoutError):
            log_exception()

        log(fstr(
            "direct_connect[{0}]: connected dest={1}",
            (self.plugin_id, dest),
        ))
        self.result.set_result(pipe)
