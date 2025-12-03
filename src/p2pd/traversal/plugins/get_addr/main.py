import asyncio
from ....utility.utils import *
from ....net.net_utils import *
from ....net.address import Address
from ....net.pipe.pipe import *
from ....node.node_defs import *
from ..traversal_plugin import TraversalPlugin

class GetAddrPlugin(TraversalPlugin):
    async def run(self, reply=None):
        # todo send get addr to dest
        msg = GetAddr({
            "meta": {
                "ttl": int(node.sys_clock.time()) + 5,
                "pipe_id": pipe_id,
                "src_buf": node.addr_bytes,
            },
            "routing": {
                "dest_buf": addr_bytes,
            },
        })
