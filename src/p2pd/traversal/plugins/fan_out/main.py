"""Meta-plugin that fans a target plugin out across viable combos.

Given a target plugin name and optional (af, route_type) constraints,
fan_out enumerates every viable (af, route_type, src, dest)
combo for the (src_map, dest_map) pair, spawns one child of the target
plugin per combo, runs them all concurrently, and returns the first
non-None pipe. Children that lose the race are cancelled and closed.

The whole point is to keep the target plugins single-purpose: each
child handles exactly one pinned attempt, fan_out owns racing,
constraint expansion, and cleanup. This means direct_connect /
reverse_connect / tcp_punch never grow their own candidate-loop
abstraction -- if you want any-pathway behaviour, wrap them in
fan_out.

Recursion is refused: target_plugin_name == "fan_out" raises.
"""
import asyncio
from aionetiface import (
    IP4, IP6, NIC_BIND, EXT_BIND, LOOPBACK_BIND,
    fstr, log, log_exception,
)
from ...traversal_plugin import Plugin
from ...strategy_registry import register
from ...traversal_utils import close_plugin
from ....node.auto_connect import race_plugin_results


def enumerate_viable_combos(
    af,
    route_type,
    src_map,
    dest_map,
):
    """Return [(af, route_type, src, dest), ...] within constraints.

    af / route_type may be None (any-pathway sentinel), in which case
    every compatible value of that axis is iterated. Pair filtering
    delegates to iter_viable_pairs, which honours route_type-specific
    distinctness rules (different NIC IPs for NIC_BIND, etc).
    """
    # Local import keeps this module free of a hard import on the
    # node package at module load time.
    from ....node.node_connect import iter_viable_pairs

    afs = [af] if af is not None else [IP4, IP6]
    if route_type is not None:
        route_types = [route_type]
    else:
        route_types = [NIC_BIND, LOOPBACK_BIND, EXT_BIND]

    combos = []
    for try_af in afs:
        if not src_map.get(try_af) or not dest_map.get(try_af):
            continue
        for try_rt in route_types:
            for src, dest in iter_viable_pairs(
                try_af, try_rt, src_map, dest_map,
            ):
                combos.append((try_af, try_rt, src, dest))
    return combos


@register(phase=None)
class FanOutPlugin(Plugin):
    """Meta-plugin: race a target plugin across every viable combo.

    Invoked explicitly (via node.connect for any-pathway requests) --
    never raced as part of auto_connect's normal plugin sweep, since
    auto_connect already does its own combo enumeration.
    """

    name = "fan_out"
    # fan_out itself doesn't bind any sockets; it is route-type-agnostic.
    route_types = (NIC_BIND, LOOPBACK_BIND, EXT_BIND)
    conf = {
        "timeout": 30,
        "set_bind": False,
        "max_pairs": 1,
    }

    def __init__(self):
        super().__init__()
        # Configured via configure_target() before run(). When
        # constraints are None they pass through to the combo
        # enumerator as the any-pathway sentinel.
        self.target_plugin_name = None  # type: Optional[str]
        self.constraint_af = None  # type: Any
        self.constraint_route_type = None  # type: Any

    def configure_target(
        self,
        target_plugin_name,
        af=None,
        route_type=None,
    ):
        """Set the child plugin and (af, route_type) constraints."""
        if target_plugin_name == "fan_out":
            raise ValueError("fan_out cannot target itself")
        self.target_plugin_name = target_plugin_name
        self.constraint_af = af
        self.constraint_route_type = route_type

    async def run(self, reply=None):
        """Spawn one child per viable combo, race their results, return the winner."""
        if self.target_plugin_name is None:
            raise ValueError("fan_out.run: configure_target() never called")
        if self.manager is None:
            raise ValueError("fan_out.run: plugin.manager not set")
        if self.src_map is None or self.dest_map is None:
            raise ValueError("fan_out.run: src_map / dest_map not set")

        manager = self.manager

        combos = enumerate_viable_combos(
            self.constraint_af,
            self.constraint_route_type,
            self.src_map,
            self.dest_map,
        )

        print("[FAN-OUT] target={0!r} af_constraint={1} route_constraint={2} combos={3}".format(
            self.target_plugin_name,
            self.constraint_af,
            self.constraint_route_type,
            len(combos),
        ))
        log(fstr(
            "fan_out[{0}]: target={1} combos={2}",
            (self.plugin_id, self.target_plugin_name, len(combos)),
        ))

        if not combos:
            self.result.set_result(None)
            return

        same_machine = (
            self.src_map.get("machine_id") == self.dest_map.get("machine_id")
        )
        log(fstr(
            "fan_out[{0}]: same_machine={1} (src_mid={2} dest_mid={3})",
            (
                self.plugin_id, same_machine,
                str(self.src_map.get("machine_id"))[:10],
                str(self.dest_map.get("machine_id"))[:10],
            ),
        ))

        children = []  # type: List[Plugin]
        for af, rt, src, dest in combos:
            try:
                child = manager.create_plugin(
                    af, rt,
                    src=src,
                    dest=dest,
                    same_machine=same_machine,
                    plugin_name=self.target_plugin_name,
                )
            except (ValueError, KeyError, OSError):
                log_exception()
                continue
            child.set_addrs(self.src_map, self.dest_map)
            child.sig_pipe = self.sig_pipe
            children.append(child)

        if not children:
            self.result.set_result(None)
            return

        # Spawn each child's run() concurrently. run_plugin awaits to
        # completion; we don't gather the tasks ourselves -- we race
        # plugin.result futures via add_done_callback so cancelling
        # this coroutine doesn't cancel underlying child plugin
        # futures (matters for plugins like tcp_punch where a
        # subprocess may resolve the result long after run_plugin
        # returns).
        tasks = [
            asyncio.ensure_future(manager.run_plugin(c))
            for c in children
        ]

        log(fstr(
            "fan_out[{0}]: racing {1} children timeout={2}s",
            (self.plugin_id, len(children), self.timeout),
        ))
        pipe, winner = await race_plugin_results(children, timeout=self.timeout)
        log(fstr(
            "fan_out[{0}]: winner={1} pipe={2}",
            (self.plugin_id,
             type(winner).__name__ if winner else "None",
             pipe is not None),
        ))

        # Cancel still-running child tasks and close every loser. The
        # winner stays in manager.plugins so the caller can use the
        # pipe; cleanup_loop will reap it later. close_plugin is safe
        # to call on plugins whose run never finished.
        for t, c in zip(tasks, children):
            if not t.done():
                t.cancel()
            if c is not winner:
                try:
                    await close_plugin(
                        c, manager.plugins, manager.inbound_pipes,
                    )
                except (OSError, asyncio.TimeoutError):
                    log_exception()

        # Drain cancellations so we don't leave Python warnings about
        # tasks that were destroyed while pending.
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        self.result.set_result(pipe)


