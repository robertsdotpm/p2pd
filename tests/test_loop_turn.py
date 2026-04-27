"""
Loop test for TURN fallback.

Same setup as test_auto_connect_turn.test_turn_fallback_returns_pipe
(local TURN server on ::1, isolate to "turn"), but runs the relay
allocation + send/recv path LOOP_COUNT times against the SAME node
pair to surface state-leak bugs across successive uses -- old
allocation handles still bound, refresh tasks not cancelled, peer
permissions not torn down between iterations, etc.

Lives in its own file so the matrix runner gives it a fresh subprocess
per CLAUDE.md heavy-tests rule.
"""

import asyncio
import unittest
from unittest.mock import patch

from aionetiface import IP6, Interface
from aionetiface.testing import AsyncTestCase
from p2pd.node.auto_connect import auto_connect

from auto_connect_helpers import (
    LOOP_COUNT,
    PORT_LOOP_TURN_A, PORT_LOOP_TURN_B,
    close_nodes, isolate_plugins, load_two_nodes, start_node_with_ifs,
)


class TestLoopTurn(AsyncTestCase):
    """TURN fallback must allocate + relay LOOP_COUNT times in a row."""

    # 3x ~30s for allocate + accept-peer + close, plus breathing room.
    async_test_timeout = 240

    async def asyncSetUp(self):
        self.ifs_a, self.ip_a, self.ifs_b, self.ip_b = await load_two_nodes(
            self, IP6, label="loop_turn",
        )
        self.node_a = await start_node_with_ifs(
            self.ifs_a, [self.ip_a], PORT_LOOP_TURN_A,
        )
        self.node_b = await start_node_with_ifs(
            self.ifs_b, [self.ip_b], PORT_LOOP_TURN_B,
        )
        self.turn_server = None
        self.get_infra_patcher = None

        self.assertIn(
            "turn", self.node_a.traversal.plugin_loaders,
            "turn plugin not installed",
        )
        await self._start_local_turn()
        isolate_plugins(self.node_a, "turn")
        print("[LOOP-TURN] setup ip_a={0} ip_b={1} plugins={2}".format(
            self.ip_a, self.ip_b,
            list(self.node_a.traversal.plugin_loaders.keys()),
        ))

    async def asyncTearDown(self):
        if self.get_infra_patcher is not None:
            self.get_infra_patcher.stop()
        if self.turn_server is not None:
            try:
                await asyncio.wait_for(self.turn_server.close(), timeout=5)
            except Exception:
                pass
        await close_nodes(self.node_b, self.node_a)

    async def _start_local_turn(self):
        """Start a local TURN server on ::1; skipTest if loopback IPv6 isn't usable."""
        from turn_server import TURNServer, make_local_turn_server_entry
        nic = await Interface()
        if IP6 not in nic.supported():
            self.skipTest("IPv6 not available on loopback interface")
        self.turn_server = TURNServer(nic)
        try:
            await self.turn_server.start()
        except OSError:
            self.skipTest("IPv6 loopback not functional (OSError on TURN server start)")
        if IP6 not in self.turn_server.started_afs():
            await self.turn_server.close()
            self.skipTest("TURN server could not bind IPv6 (::1 unavailable)")
        local_entry = make_local_turn_server_entry(
            port=self.turn_server.af_ports.get(IP6, self.turn_server.port),
            af=IP6,
        )
        self.get_infra_patcher = patch(
            "p2pd.traversal.plugins.turn.main.get_infra",
            return_value=[[local_entry]],
        )
        self.get_infra_patcher.start()

    async def test_loop(self):
        for i in range(LOOP_COUNT):
            label = "iter {0}/{1}".format(i + 1, LOOP_COUNT)
            print("[LOOP-TURN] === {0} START ===".format(label))
            pipe, plugin = await asyncio.wait_for(
                auto_connect(self.node_a, self.node_b.addr_bytes, timeout=25),
                timeout=35,
            )
            self.assertIsNotNone(
                pipe, "{0}: TURN fallback returned no pipe".format(label),
            )
            self.assertEqual(
                type(plugin).__name__, "TURNPlugin",
                "{0}: expected TURNPlugin pipe, got {1}".format(
                    label, type(plugin).__name__,
                ),
            )
            print("[LOOP-TURN] {0} OK".format(label))
            try:
                await asyncio.wait_for(pipe.close(), timeout=5)
            except (asyncio.TimeoutError, OSError, ConnectionError):
                pass
            # TURN allocations linger on the server side until the
            # client refreshes or the lifetime expires; give the close
            # path time to actually retract permissions before the next
            # iteration tries to allocate again.
            await asyncio.sleep(1.0)


if __name__ == "__main__":
    unittest.main()
