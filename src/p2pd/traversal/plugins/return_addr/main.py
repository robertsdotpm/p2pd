from ....utility.utils import *
from ..traversal_plugin import TraversalPlugin
from ...signaling.signal_msgs import ReturnAddr

class ReturnAddrPlugin(TraversalPlugin):
    async def run(self, reply=None):
        msg = ReturnAddr({})

        # Send this message to the dest_addr for this plugin instance.
        await self.signal_msg_sender(msg)