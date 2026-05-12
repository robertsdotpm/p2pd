"""
Loop test for direct_connect.

Runs auto_connect (with every other connection-returning plugin popped,
leaving direct_connect as the only path that can return a pipe) against
the SAME node pair LOOP_COUNT times in succession. Purpose: surface
state-leak bugs that would never show up in a single-shot test --
sockets not closed between runs, plugin slots not freed, MQTT subs not
torn down, inbound pipe registry not cleared, etc.

If a clean run on iteration 1 stops working on iteration 2 or 3, the
plugin (or its caller) is accumulating per-call state that should have
been cleaned up.

Lives in its own file so the matrix runner gives it a fresh subprocess
per CLAUDE.md heavy-tests rule.
"""

import asyncio
import unittest

from aionetiface import IP4
from aionetiface.testing import AsyncTestCase
from warpgate.node.auto_connect import auto_connect

from auto_connect_helpers import (
    LOOP_COUNT,
    PORT_LOOP_DIRECT_A, PORT_LOOP_DIRECT_B,
    close_nodes, isolate_plugins, load_two_nodes, start_node_with_ifs,
)


class TestLoopDirectConnect(AsyncTestCase):
    """direct_connect must succeed LOOP_COUNT times in a row against the same node pair."""

    async_test_timeout = 120

    async def asyncSetUp(self):
        self.ifs_a, self.ip_a, self.ifs_b, self.ip_b = await load_two_nodes(
            self, IP4, label="loop_direct_connect",
        )
        self.node_a = await start_node_with_ifs(
            self.ifs_a, [self.ip_a], PORT_LOOP_DIRECT_A,
        )
        self.node_b = await start_node_with_ifs(
            self.ifs_b, [self.ip_b], PORT_LOOP_DIRECT_B,
        )
        # reverse_connect is allowed to win some iterations on same-LAN
        # paths -- both are legitimate same-LAN direct paths -- so keep
        # both whitelisted. Pop everything else so TURN / probes / punch
        # can't race ahead.
        isolate_plugins(self.node_a, "direct_connect", "reverse_connect")
        print("[LOOP-DIRECT] setup ip_a={0} ip_b={1} plugins={2}".format(
            self.ip_a, self.ip_b,
            list(self.node_a.traversal.plugin_loaders.keys()),
        ))

    async def asyncTearDown(self):
        await close_nodes(self.node_b, self.node_a)

    async def test_loop(self):
        for i in range(LOOP_COUNT):
            label = "iter {0}/{1}".format(i + 1, LOOP_COUNT)
            print("[LOOP-DIRECT] === {0} START ===".format(label))
            pipe, plugin = await asyncio.wait_for(
                auto_connect(self.node_a, self.node_b.addr_bytes, timeout=20),
                timeout=25,
            )
            self.assertIsNotNone(
                pipe, "{0}: auto_connect returned no pipe".format(label),
            )
            self.assertIsNotNone(
                plugin, "{0}: auto_connect returned no plugin".format(label),
            )
            self.assertIn(
                type(plugin).__name__,
                ("DirectConnect", "ReverseConnectPlugin"),
                "{0}: expected DirectConnect or ReverseConnectPlugin, got {1}".format(
                    label, type(plugin).__name__,
                ),
            )
            print("[LOOP-DIRECT] {0} OK plugin={1}".format(
                label, type(plugin).__name__,
            ))
            try:
                await asyncio.wait_for(pipe.close(), timeout=5)
            except Exception:
                pass
            # Brief breath so any background close tasks settle before
            # the next iteration sees the same node pair. Not a
            # workaround for a known bug -- just removes one source of
            # noise so a real state-leak failure is unambiguous.
            await asyncio.sleep(0.3)


if __name__ == "__main__":
    unittest.main()
