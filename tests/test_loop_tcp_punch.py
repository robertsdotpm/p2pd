"""
Loop test for tcp_punch.

Runs auto_connect with every other plugin popped so tcp_punch is the
only candidate, repeated LOOP_COUNT times against the SAME node pair to
surface state-leak bugs across successive punches (NAT prediction
sockets not freed, predict_alloc state retained, mapping windows not
recycled, ...).

Inherits the same skip conditions as test_auto_connect_punch since the
same prerequisites apply (no same-machine, no symmetric NAT, real
multi-NIC topology).

Lives in its own file so the matrix runner gives it a fresh subprocess
per CLAUDE.md heavy-tests rule.
"""

import asyncio
import unittest

from aionetiface import IP4, SYMMETRIC_NAT, parse_node_addr
from aionetiface.testing import AsyncTestCase
from p2pd.node.auto_connect import auto_connect, auto_combos, is_same_machine

from auto_connect_helpers import (
    LOOP_COUNT,
    PORT_LOOP_TCP_PUNCH_A, PORT_LOOP_TCP_PUNCH_B,
    PUNCH_TEST_CONF,
    close_nodes, isolate_plugins, load_two_nodes, start_node_with_ifs,
)


def has_symmetric_nat(node):
    for af in (IP4,):
        af_dict = node.addr_map.get(af) or {}
        for info in af_dict.values():
            nat = info.get("nat") or {}
            if nat.get("type") == SYMMETRIC_NAT:
                return True
            if nat.get("is_hard"):
                return True
    return False


def is_loopback_addr(s):
    if not s:
        return False
    s = str(s)
    if s.startswith("127."):
        return True
    if s == "::1" or s.startswith("::1"):
        return True
    return False


def all_punch_combos_loopback(node, dest_map):
    from p2pd.traversal.traversal_utils import select_dest_ipr
    found_any = False
    for combo in auto_combos(node, node.addr_map, dest_map):
        plugin_name, af, route_type, src, dest = combo
        if plugin_name != "tcp_punch":
            continue
        same_pc = True
        if src.get("machine_id") != dest.get("machine_id"):
            same_pc = False
            continue
        found_any = True
        chosen = select_dest_ipr(af, same_pc, src, dest, [route_type])
        if chosen is None:
            continue
        if not is_loopback_addr(chosen):
            return False
    return found_any


class TestLoopTcpPunch(AsyncTestCase):
    """tcp_punch must succeed LOOP_COUNT times in a row."""

    # Punch needs a longer per-test budget than the default 90s testing.py cap
    # because the inner punch round-trip wait_for is 60s, and we're firing 3
    # in a row.
    async_test_timeout = 240

    async def asyncSetUp(self):
        self.ifs_a, self.ip_a, self.ifs_b, self.ip_b = await load_two_nodes(
            self, IP4, label="loop_tcp_punch",
        )
        self.node_a = await start_node_with_ifs(
            self.ifs_a, [self.ip_a], PORT_LOOP_TCP_PUNCH_A, conf=PUNCH_TEST_CONF,
        )
        self.node_b = await start_node_with_ifs(
            self.ifs_b, [self.ip_b], PORT_LOOP_TCP_PUNCH_B, conf=PUNCH_TEST_CONF,
        )

        if is_same_machine(self.node_a.addr_map, self.node_b.addr_map):
            self.skipTest(
                "same-machine peers don't need NAT punching; "
                "direct_connect over loopback covers this topology"
            )
        dest_map_for_combos = parse_node_addr(self.node_b.addr_bytes)
        if all_punch_combos_loopback(self.node_a, dest_map_for_combos):
            self.skipTest(
                "every punch combo resolves to a loopback dest; "
                "punch path doesn't drive same-machine loopback"
            )
        if has_symmetric_nat(self.node_a) or has_symmetric_nat(self.node_b):
            self.skipTest(
                "punch can't traverse symmetric NAT; node_a sym={0} "
                "node_b sym={1}".format(
                    has_symmetric_nat(self.node_a),
                    has_symmetric_nat(self.node_b),
                )
            )
        self.assertIn(
            "tcp_punch", self.node_a.traversal.plugin_loaders,
            "punch plugin not installed (enable_punching=False?)",
        )
        isolate_plugins(self.node_a, "tcp_punch")
        print("[LOOP-PUNCH] setup ip_a={0} ip_b={1} plugins={2}".format(
            self.ip_a, self.ip_b,
            list(self.node_a.traversal.plugin_loaders.keys()),
        ))

    async def asyncTearDown(self):
        await close_nodes(self.node_b, self.node_a)

    async def test_loop(self):
        for i in range(LOOP_COUNT):
            label = "iter {0}/{1}".format(i + 1, LOOP_COUNT)
            print("[LOOP-PUNCH] === {0} START ===".format(label))
            pipe, plugin = await asyncio.wait_for(
                auto_connect(self.node_a, self.node_b.addr_bytes, timeout=50),
                timeout=60,
            )
            self.assertIsNotNone(
                pipe, "{0}: tcp_punch returned no pipe".format(label),
            )
            self.assertEqual(
                type(plugin).__name__,
                "PunchPlugin",
                "{0}: expected PunchPlugin, got {1}".format(
                    label, type(plugin).__name__,
                ),
            )
            print("[LOOP-PUNCH] {0} OK".format(label))
            try:
                await asyncio.wait_for(pipe.close(), timeout=5)
            except Exception:
                pass
            # Punch leaves more residue than direct/reverse: a longer
            # breath here gives NAT mapping windows time to recycle
            # before the next iteration so a real state-leak failure
            # isn't masked by transient mapping reuse.
            await asyncio.sleep(1.0)


if __name__ == "__main__":
    unittest.main()
