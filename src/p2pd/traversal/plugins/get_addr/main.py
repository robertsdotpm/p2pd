from aionetiface import *
from ..traversal_plugin import TraversalPlugin
from ....protocol.signaling.signal_msgs import GetAddr

class GetAddrPlugin(TraversalPlugin):
    async def run(self, reply=None):
        if reply:
            self.result.set_result(reply.meta.src["bytes"])
            return

        print("in get addr plugin")
        msg = GetAddr()

        # Pass request to return addr plugin on dest.
        msg.meta.plugin_name = "return_addr"

        # Send this message to the dest_addr for this plugin instance.
        print(self.signal_msg_sender)
        await self.signal_msg_sender(msg)