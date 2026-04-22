"""Traversal plugin for direct (non-NATed) connections."""
from typing import Any, Optional
import asyncio
from aionetiface import IP4, IP6, TCP, Pipe, log_exception, to_b, fstr
from ....node.node_defs import CON_ID_MSG
from ...traversal_plugin import TraversalPlugin


class DirectConnect(TraversalPlugin):
    """Traversal plugin that attempts a straightforward TCP connection to the peer."""

    async def run(self, reply: Optional[Any] = None) -> None:
        """Open a direct TCP connection to the peer and store the resulting pipe."""
        # Connect to this address.
        dest = (
            str(self.dest_info["ip"]),
            self.dest_info["port"],
        )

        # (1) Get first interface for AF.
        # (2) Build a 'route' from it with it's main NIC IP.
        # (3) Bind to the route at port 0. Return itself.
        if self.af == IP4:
            route = await self.nic.route(self.af).bind()
        if self.af == IP6:
            if "fe80" == dest[0][:4]:
                route = self.nic.route(self.af)
                await route.bind(ips=str(route.link_locals[0]))
            else:
                route = await self.nic.route(self.af).bind()

        # Connect to destination.
        try:
            pipe = await Pipe(TCP, dest, route).connect()
        except (OSError, ConnectionError, asyncio.TimeoutError):
            log_exception()
            pipe = None

        if pipe is None:
            return

        if pipe.sock is None:
            return

        await pipe.send(CON_ID_MSG + to_b(fstr(" {0}\n", (self.plugin_id,))))
        self.result.set_result(pipe)
