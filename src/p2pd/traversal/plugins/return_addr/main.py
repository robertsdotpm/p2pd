from aionetiface import *
from ...traversal_plugin import TraversalPlugin
from ....protocol.traversal.proto_msg import ReturnAddr

class ReturnAddrPlugin(TraversalPlugin):
    async def run(self, reply=None):
        msg = ReturnAddr()
        msg.meta.plugin_name = "get_addr"

        # Send this message to the dest_addr for this plugin instance.
        try:
            await self.send_signal_msg(msg)
        except Exception:
            log_exception()

        self.result.set_result("Done")