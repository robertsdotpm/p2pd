"""Traversal plugin that inverts the connection direction."""
from typing import Any, Optional
from aionetiface import fstr, log
from ...traversal_plugin import TraversalPlugin
from ....protocol.proto_msg import ConMsg


class ReverseConnectPlugin(TraversalPlugin):
    """Traversal plugin that asks the remote peer to initiate the TCP connection."""

    async def run(self, reply: Optional[Any] = None) -> None:
        """Signal the remote peer to connect back to us and await the inbound pipe."""
        log(fstr(
            "reverse_connect[{0}]: af={1} src_info={2} dest_info={3}",
            (self.plugin_id, self.af, self.src_info, self.dest_info),
        ))
        msg = ConMsg()
        msg.meta.plugin_name = "direct_connect"
        self.register_inbound()
        log(fstr(
            "reverse_connect[{0}]: registered inbound, sending signal",
            (self.plugin_id,),
        ))
        await self.send_signal_msg(msg)
        log(fstr(
            "reverse_connect[{0}]: signal sent, awaiting inbound",
            (self.plugin_id,),
        ))
        con = await self.wait_for_inbound()
        log(fstr(
            "reverse_connect[{0}]: inbound arrived, setting result",
            (self.plugin_id,),
        ))
        self.result.set_result(con)

PLUGIN_CLASS = ReverseConnectPlugin
