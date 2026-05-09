"""Traversal plugin for direct (non-NATed) connections.

Plain TCP connect from src_info["ip"] to dest_info["ip"]:dest_info["port"].

Routing decisions (which IP per route_type, v6 link-local %scope, loopback
alias selection) all live in traversal_utils.resolve_pair before run()
fires; this plugin reads the pre-resolved (ip, port) pair and dials.
"""
from typing import Any, Optional
import asyncio
from aionetiface import TCP, Pipe, log, log_exception, fstr, to_b
from ...traversal_plugin import Plugin
from ...strategy_registry import register
from ...traversal_utils import bind_route_for
from .con_id_frame import CON_ID_PREFIX


@register(phase="direct")
class DirectConnect(Plugin):
    """Traversal plugin that attempts a straightforward TCP connection to the peer."""

    name = "direct_connect"
    transport = "tcp"

    async def run(self, reply: Optional[Any] = None) -> None:
        """Open a direct TCP connection to the peer and store the resulting pipe."""
        src_ip = self.src_info["ip"]
        dest = (self.dest_info["ip"], self.dest_info["port"])
        log(fstr(
            "direct_connect[{0}]: af={1} src={2} dest={3} reply={4}",
            (self.plugin_id, self.af, src_ip, dest, reply is not None),
        ))

        # Bind to the resolved local IP for this combo.  resolve_pair
        # already picked the right local source -- NIC IP for NIC_BIND
        # / EXT_BIND, per-pubkey alias for LOOPBACK_BIND, link-local
        # with %scope baked in for v6 fe80::.  bind_route_for picks
        # Interface("default") for loopback IPs and self.nic otherwise.
        route = await bind_route_for(self.nic, self.af, src_ip)
        if route is None:
            log(fstr(
                "direct_connect[{0}]: bind to {1} failed",
                (self.plugin_id, src_ip),
            ))
            self.result.set_result(None)
            return

        try:
            pipe = await asyncio.wait_for(
                Pipe(TCP, dest, route).connect(),
                timeout=4.0,
            )
        except (OSError, ConnectionError, asyncio.TimeoutError) as exc:
            log(fstr(
                "direct_connect[{0}]: connect to {1} failed: {2!r}",
                (self.plugin_id, dest, exc),
            ))
            log_exception()
            self.result.set_result(None)
            return

        if pipe is None or pipe.sock is None:
            log(fstr(
                "direct_connect[{0}]: connect to {1} returned no usable pipe",
                (self.plugin_id, dest),
            ))
            self.result.set_result(None)
            return

        # In-band ConId frame: write b"P2P-CID:<plugin_id>\n" as the
        # very first bytes on the new TCP pipe.  Same channel as the
        # data pipe means no cross-channel race with a separate signal
        # round-trip -- the responder's node_protocol peels off this
        # frame on the first inbound message and resolves the
        # reverse_connect inbound future for plugin_id directly.
        con_id_frame = CON_ID_PREFIX + to_b(self.plugin_id) + b"\n"
        try:
            await pipe.send(con_id_frame)
        except (OSError, ConnectionError, asyncio.TimeoutError) as exc:
            log(fstr(
                "direct_connect[{0}]: ConId send failed: {1!r}",
                (self.plugin_id, exc),
            ))
            log_exception()

        self.result.set_result(pipe)


# direct_connect no longer owns any signal-channel messages.
# The connection-request side stays at the core layer (ConMsg, registered
# centrally by build_core_sig_proto). The follow-up rendezvous that used
# to be a signal-channel ConIdMsg now travels in-band as the very first
# bytes on the new TCP pipe (see con_id_frame.CON_ID_PREFIX). One channel,
# no cross-channel race.
