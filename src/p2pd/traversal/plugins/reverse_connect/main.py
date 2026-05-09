"""Traversal plugin that inverts the connection direction."""
from typing import Any, Optional
from aionetiface import fstr, log
from ...traversal_plugin import Plugin
from ...strategy_registry import register
from ....protocol.proto_msg import ConMsg


@register(phase="direct")
class ReverseConnectPlugin(Plugin):
    """Ask the peer to initiate a direct TCP connect back at us."""

    name = "reverse_connect"
    transport = "tcp"

    async def run(self, reply: Optional[Any] = None) -> None:
        """Signal the peer to dial us; await the inbound pipe."""
        msg = ConMsg()
        msg.meta.plugin_name = "direct_connect"
        # Reserve the inbound future BEFORE sending the signal -- a
        # fast peer could connect back before we register, otherwise.
        self.register_inbound()
        await self.send_signal_msg(msg)
        log(fstr(
            "reverse_connect[{0}]: signal sent, awaiting inbound",
            (self.plugin_id,),
        ))
        pipe = await self.wait_for_inbound()
        self.result.set_result(pipe)
