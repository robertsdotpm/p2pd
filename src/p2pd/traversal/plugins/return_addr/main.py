"""Traversal plugin for signalling a public return address."""
from typing import Any, Optional
from aionetiface import *
from ...traversal_plugin import TraversalPlugin
from ....protocol.traversal.proto_msg import ReturnAddr


class ReturnAddrPlugin(TraversalPlugin):
    """Traversal plugin that replies to a GetAddr request with the sender's own address."""

    async def run(self, reply: Optional[Any] = None) -> None:
        """Send a ReturnAddr signal message back to the requester with our current address."""
        msg = ReturnAddr()
        msg.meta.plugin_name = "get_addr"

        # Send this message to the dest_addr for this plugin instance.
        try:
            await self.send_signal_msg(msg)
        except (OSError, ConnectionError, asyncio.TimeoutError):
            log_exception()

        self.result.set_result("Done")
