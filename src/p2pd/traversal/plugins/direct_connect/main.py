"""Traversal plugin for direct (non-NATed) connections."""
from typing import Any, Optional
import asyncio
from aionetiface import IP4, IP6, TCP, Pipe, log, log_exception, to_b, fstr
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
        log(fstr(
            "direct_connect[{0}]: af={1} dest={2} nic.id={3} reply={4}",
            (self.plugin_id, self.af, dest, getattr(self.nic, "id", "?"), reply is not None),
        ))
        print("[DIRECT-DBG] plugin_id={0} af={1} dest_ip={2} dest_port={3} src_loopback={4} nic_id={5}".format(
            self.plugin_id, self.af, dest[0], dest[1],
            self.src_info.get("loopback") if self.src_info else None,
            getattr(self.nic, "id", "?"),
        ))

        # (1) Get first interface for AF.
        # (2) Build a 'route' from it with it's main NIC IP.
        # (3) Bind to the route at port 0. Return itself.
        if self.af == IP4:
            # Same-machine cross-subnet: when dest is alice/bob's
            # 127.X.Y.Z loopback alias, the source must also be
            # loopback or the OS won't route the SYN over lo
            # (Windows drops cross-subnet src->loopback dest entirely).
            # alice's own loopback alias is already in src_info; fall
            # back to 127.0.0.1 if for any reason it's missing.
            if dest[0].startswith("127."):
                src_lo = self.src_info.get("loopback")
                src_ip = str(src_lo) if src_lo is not None else "127.0.0.1"
                print("[DIRECT-DBG] picking loopback src_ip={0} for dest={1}".format(src_ip, dest))
                route = self.nic.route(self.af)
                await route.bind(ips=src_ip)
            else:
                print("[DIRECT-DBG] non-loopback dest, default route bind for dest={0}".format(dest))
                route = await self.nic.route(self.af).bind()
        if self.af == IP6:
            if "fe80" == dest[0][:4]:
                route = self.nic.route(self.af)
                await route.bind(ips=str(route.link_locals[0]))
            else:
                route = await self.nic.route(self.af).bind()

        log(fstr(
            "direct_connect[{0}]: bound, attempting TCP connect to {1}",
            (self.plugin_id, dest),
        ))

        # Connect to destination.
        try:
            pipe = await Pipe(TCP, dest, route).connect()
        except (OSError, ConnectionError, asyncio.TimeoutError) as exc:
            print("[DIRECT-DBG] TCP connect to {0} raised: {1!r}".format(dest, exc))
            log_exception()
            pipe = None

        if pipe is None:
            print("[DIRECT-DBG] TCP connect to {0} returned None".format(dest))
            log(fstr(
                "direct_connect[{0}]: TCP connect to {1} returned None",
                (self.plugin_id, dest),
            ))
            return
        print("[DIRECT-DBG] TCP connect to {0} OK, pipe={1!r}".format(dest, pipe))

        if pipe.sock is None:
            log(fstr(
                "direct_connect[{0}]: pipe.sock is None after connect",
                (self.plugin_id,),
            ))
            return

        await pipe.send(CON_ID_MSG + to_b(fstr(" {0}\n", (self.plugin_id,))))
        log(fstr(
            "direct_connect[{0}]: sent CON_ID_MSG, setting result",
            (self.plugin_id,),
        ))
        self.result.set_result(pipe)

PLUGIN_CLASS = DirectConnect
