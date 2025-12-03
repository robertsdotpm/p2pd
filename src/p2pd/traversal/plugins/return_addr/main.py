import asyncio
from ....utility.utils import *
from ....net.net_utils import *
from ....net.address import Address
from ....net.pipe.pipe import *
from ....node.node_defs import *
from ..traversal_plugin import TraversalPlugin

class ReturnAddrPlugin(TraversalPlugin):
    async def run(self, reply=None):
        # todo send return addr to dest
        msg = ReturnAddr({
            "meta": {
                "ttl": int(f_time()) + 5,
                "pipe_id": msg.meta.pipe_id,
                "src_buf": addr_bytes,
            },
            "routing": {
                "dest_buf": msg.meta.src_buf,
            },
        })

        msg.cipher.vk = vk
        return msg