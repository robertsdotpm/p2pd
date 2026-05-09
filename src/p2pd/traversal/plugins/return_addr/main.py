"""Traversal plugin for signalling a public return address."""
import asyncio
from aionetiface import log, log_exception, fstr
from ...traversal_plugin import Plugin
from ...strategy_registry import register
from ....protocol.proto_msg import ReturnAddr


@register(phase=None)
class ReturnAddrPlugin(Plugin):
    """Traversal plugin that replies to a GetAddr request with the sender's own address."""

    name = "return_addr"

    async def run(self, reply=None):
        """Send a ReturnAddr signal message back to the requester with our current address."""
        log(fstr(
            "return_addr[{0}]: replying to GetAddr from peer",
            (self.plugin_id,),
        ))
        msg = ReturnAddr()
        msg.meta.plugin_name = "get_addr"

        # Send this message to the dest_addr for this plugin instance.
        try:
            await self.send_signal(msg)
            log(fstr(
                "return_addr[{0}]: ReturnAddr sent",
                (self.plugin_id,),
            ))
        except (OSError, ConnectionError, asyncio.TimeoutError) as exc:
            log(fstr(
                "return_addr[{0}]: send_signal FAILED: {1}",
                (self.plugin_id, repr(exc)),
            ))
            log_exception()

        self.result.set_result("Done")
