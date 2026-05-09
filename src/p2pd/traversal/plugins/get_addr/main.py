"""Traversal plugin that resolves peer addresses via signalling."""
from aionetiface import log, fstr
from ...traversal_plugin import Plugin
from ...strategy_registry import register
from ....protocol.proto_msg import GetAddr


@register(phase=None)
class GetAddrPlugin(Plugin):
    """Traversal plugin that requests and returns the peer's current network address."""

    name = "get_addr"

    async def run(self, reply=None):
        """Resolve the peer's address: extract from reply or send a GetAddr request."""
        if reply:
            log(fstr(
                "get_addr[{0}]: reply received -- resolving from src",
                (self.plugin_id,),
            ))
            self.result.set_result(reply.meta.src_map["bytes"])
            return

        log(fstr(
            "get_addr[{0}]: no reply -- sending GetAddr to peer",
            (self.plugin_id,),
        ))
        msg = GetAddr()

        # Pass request to return addr plugin on dest.
        msg.meta.plugin_name = "return_addr"

        # Send this message to the dest_addr for this plugin instance.
        await self.send_signal(msg)

