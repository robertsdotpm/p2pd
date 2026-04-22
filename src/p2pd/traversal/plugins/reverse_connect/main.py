from aionetiface import *
from ...traversal_plugin import TraversalPlugin
from ....protocol.traversal.proto_msg import ConMsg


class ReverseConnectPlugin(TraversalPlugin):
    """Traversal plugin that asks the remote peer to initiate the TCP connection."""

    async def run(self, reply=None):
        # type: (Optional[Any]) -> None
        msg = ConMsg()
        msg.meta.plugin_name = "direct_connect"
        self.register_inbound()
        await self.send_signal_msg(msg)
        con = await self.wait_for_inbound()
        self.result.set_result(con)
