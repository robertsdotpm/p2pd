"""Traversal plugin that inverts the connection direction."""
from typing import Any, Optional
from aionetiface import fstr, log
from ...traversal_plugin import TraversalPlugin
from ....protocol.proto_msg import ConMsg


class ReverseConnectPlugin(TraversalPlugin):
    """Traversal plugin that asks the remote peer to initiate the TCP connection."""

    async def run(self, reply: Optional[Any] = None) -> None:
        """Signal the remote peer to connect back to us and await the inbound pipe."""
        print("[REV-CON] reverse_connect.run plugin_id={0!r} af={1}".format(
            self.plugin_id, self.af,
        ))
        log(fstr(
            "reverse_connect[{0}]: af={1} src_info={2} dest_info={3}",
            (self.plugin_id, self.af, self.src_info, self.dest_info),
        ))
        msg = ConMsg()
        msg.meta.plugin_name = "direct_connect"
        self.register_inbound()
        print("[REV-CON]   registered inbound future under plugin_id={0!r}".format(
            self.plugin_id,
        ))
        log(fstr(
            "reverse_connect[{0}]: registered inbound, sending signal",
            (self.plugin_id,),
        ))
        print("[REV-CON]   sending ConMsg signal to peer...")
        await self.send_signal_msg(msg)
        print("[REV-CON]   ConMsg sent; awaiting inbound future for plugin_id={0!r}".format(
            self.plugin_id,
        ))
        log(fstr(
            "reverse_connect[{0}]: signal sent, awaiting inbound",
            (self.plugin_id,),
        ))
        con = await self.wait_for_inbound()
        print("[REV-CON]   inbound future RESOLVED for plugin_id={0!r} pipe={1!r}".format(
            self.plugin_id, con,
        ))
        log(fstr(
            "reverse_connect[{0}]: inbound arrived, setting result",
            (self.plugin_id,),
        ))
        self.result.set_result(con)

PLUGIN_CLASS = ReverseConnectPlugin

# Default plugin timeout (10s) is too tight: reverse_connect waits for
# the *partner's* direct_connect plugin to finish (its TCP connect +
# its post-connect await send_signal_msg(ConIdMsg) round-trip) plus the
# signal-channel hop back to alice's handle_con_id. The XP trace
# explicitly showed "reverse_connect plugin probably timed out before
# this signal arrived" because the rendezvous arrived after the 10s
# wall. 30s leaves room for the partner's bumped 25s direct_connect
# budget plus signal jitter.
PLUGIN_CONF = {"timeout": 30}
