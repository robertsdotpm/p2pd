from aionetiface import *
from ..traversal_plugin import TraversalPlugin
from ....protocol.signaling.signal_msgs import ReturnAddr

class ReturnAddrPlugin(TraversalPlugin):
    async def run(self, reply=None):
        msg = ReturnAddr()
        msg.meta.plugin_name = "get_addr"

        print("in return addr")

        # Send this message to the dest_addr for this plugin instance.
        try:
            await self.signal_msg_sender(msg)
        except Exception:
            print("ReturnAddrPlugin error in addr")
            what_exception()

        self.result.set_result("Done")