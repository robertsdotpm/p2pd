import asyncio
from aionetiface import *
from ....node.node_defs import *
from ...traversal_plugin import TraversalPlugin

class DirectConnect(TraversalPlugin):
    async def run(self, reply=None):
        print("in direct connect plugin")

        # Connect to this address.
        dest = (
            str(self.dest_info["ip"]),
            self.dest_info["port"],
        )

        print("direct connect dest = ", dest)

        # (1) Get first interface for AF.
        # (2) Build a 'route' from it with it's main NIC IP.
        # (3) Bind to the route at port 0. Return itself.
        if self.af == IP4:
            route = await self.nic.route(self.af).bind()
        if self.af == IP6:
            if "fe80" == dest[0][:4]:
                route = self.nic.route(self.af)
                await route.bind(
                    ips=str(route.link_locals[0])
                )
            else:
                route = await self.nic.route(self.af).bind()

        # Connect to destination.
        try:
            pipe = await Pipe(TCP, dest, route).connect()
        except Exception:
            print("direct connect pipe open failed")
            log_exception()
            pipe = None

        if pipe is None:
            return
        
        if pipe.sock is None:
            return

        await pipe.send(CON_ID_MSG + to_b(fstr(" {0}\n", (self.pipe_id,))))
        self.result.set_result(pipe)