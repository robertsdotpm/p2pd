from aionetiface import *
from ...traversal_plugin import TraversalPlugin
from ....protocol.traversal.proto_msg import GetAddr


class GetAddrPlugin(TraversalPlugin):
    """Traversal plugin that requests and returns the peer's current network address."""

    async def run(self, reply=None):
        # type: (Optional[Any]) -> None
        if reply:
            self.result.set_result(reply.meta.src["bytes"])
            return

        msg = GetAddr()

        # Pass request to return addr plugin on dest.
        msg.meta.plugin_name = "return_addr"

        # Send this message to the dest_addr for this plugin instance.
        await self.send_signal_msg(msg)
