import asyncio
from aionetiface import *
from ...traversal_plugin import TraversalPlugin
from ....protocol.traversal.proto_msg import ConMsg

class ReverseConnectPlugin(TraversalPlugin):
    async def run(self, reply=None):
        print("inside reverse connect plugin")
        print("using pipe id = ", self.pipe_id)
        msg = ConMsg()
        msg.meta.plugin_name = "direct_connect"

        # Register future to receive back inbound con.
        self.pipes[self.pipe_id] = asyncio.Future()

        # Send reverse request.
        await self.signal_msg_sender(msg)

        # Await con.
        con = await self.pipes[self.pipe_id]
        print("await con = ", con)
        self.result.set_result(con)