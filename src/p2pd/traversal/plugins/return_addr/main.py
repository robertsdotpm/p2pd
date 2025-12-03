import asyncio
from ....utility.utils import *
from ....net.net_utils import *
from ....net.address import Address
from ....net.pipe.pipe import *
from ....node.node_defs import *
from ..traversal_plugin import TraversalPlugin
from ...signaling.signal_msgs import ReturnAddr

class ReturnAddrPlugin(TraversalPlugin):
    async def run(self, reply=None):
        msg = ReturnAddr({})
        await self.signal_msg_sender(msg)