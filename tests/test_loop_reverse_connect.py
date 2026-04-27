"""
Loop test for reverse_connect — same purpose as test_loop_direct_connect.

Runs auto_connect with every other plugin popped so reverse_connect is
the only path that can return a pipe, repeated LOOP_COUNT times against
the SAME node pair to surface state-leak bugs across successive uses.

Lives in its own file so the matrix runner gives it a fresh subprocess
per CLAUDE.md heavy-tests rule.
"""

import asyncio
import unittest

from aionetiface import IP4
from aionetiface.testing import AsyncTestCase
from p2pd.node.auto_connect import auto_connect

from auto_connect_helpers import (
    LOOP_COUNT,
    PORT_LOOP_REVERSE_A, PORT_LOOP_REVERSE_B,
    close_nodes, isolate_plugins, load_two_nodes, start_node_with_ifs,
)


class TestLoopReverseConnect(AsyncTestCase):
    """reverse_connect must succeed LOOP_COUNT times in a row."""

    async_test_timeout = 120

    async def asyncSetUp(self):
        self.ifs_a, self.ip_a, self.ifs_b, self.ip_b = await load_two_nodes(
            self, IP4, label="loop_reverse_connect",
        )
        self.node_a = await start_node_with_ifs(
            self.ifs_a, [self.ip_a], PORT_LOOP_REVERSE_A,
        )
        self.node_b = await start_node_with_ifs(
            self.ifs_b, [self.ip_b], PORT_LOOP_REVERSE_B,
        )
        isolate_plugins(self.node_a, "reverse_connect")
        print("[LOOP-REVERSE] setup ip_a={0} ip_b={1} plugins={2}".format(
            self.ip_a, self.ip_b,
            list(self.node_a.traversal.plugin_loaders.keys()),
        ))

    async def asyncTearDown(self):
        await close_nodes(self.node_b, self.node_a)

    async def test_loop(self):
        for i in range(LOOP_COUNT):
            label = "iter {0}/{1}".format(i + 1, LOOP_COUNT)
            print("[LOOP-REVERSE] === {0} START ===".format(label))
            pipe, plugin = await asyncio.wait_for(
                auto_connect(self.node_a, self.node_b.addr_bytes, timeout=20),
                timeout=25,
            )
            self.assertIsNotNone(
                pipe, "{0}: reverse_connect returned no pipe".format(label),
            )
            self.assertIsNotNone(plugin)
            self.assertEqual(
                type(plugin).__name__,
                "ReverseConnectPlugin",
                "{0}: expected ReverseConnectPlugin, got {1}".format(
                    label, type(plugin).__name__,
                ),
            )
            print("[LOOP-REVERSE] {0} OK".format(label))
            try:
                await asyncio.wait_for(pipe.close(), timeout=5)
            except Exception:
                pass
            await asyncio.sleep(0.3)


if __name__ == "__main__":
    unittest.main()
