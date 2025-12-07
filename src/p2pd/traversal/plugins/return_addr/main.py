from ....utility.utils import *
from ..traversal_plugin import TraversalPlugin
from ...signaling.signal_msgs import ReturnAddr

class ReturnAddrPlugin(TraversalPlugin):
    async def run(self, reply=None):
        msg = ReturnAddr()

        print("in return addr")

        # Send this message to the dest_addr for this plugin instance.
        try:
            await self.signal_msg_sender(msg)
        except:
            what_exception()

        self.result.set_result("Done")