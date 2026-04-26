"""
Integration tests — TURN fallback.

Strict on multi-NIC machines: once require_split_or_fail has handed us
two real NICs each carrying an IPv6 IP, every subsequent failure is a
real failure -- no skipTest fallbacks. The TURN-server-side bind (::1)
remains a legitimate skip path because it's environmental, not a p2pd
bug.
"""

import asyncio
import unittest
from unittest.mock import patch

from aionetiface import IP6, Interface
from aionetiface.testing import AsyncTestCase
from p2pd.node.auto_connect import auto_connect

from auto_connect_helpers import (
    PORT_TURN_A_T1, PORT_TURN_B_T1, PORT_TURN_A_T2,
    PORT_TURN_A_T3, PORT_TURN_B_T3,
    close_nodes, load_two_nodes, start_node_with_ifs,
)


def log_pipe(label, pipe, plugin=None):
    print("[TURN-TEST] {0}: pipe={1!r} sock={2!r} plugin={3}".format(
        label, pipe, getattr(pipe, "sock", None),
        type(plugin).__name__ if plugin is not None else None,
    ))


class TestAutoConnectTurnFallback(AsyncTestCase):
    """auto_connect falls back to the TURN relay when all direct plugins are removed."""

    async def asyncSetUp(self):
        self.ifs_a, self.ip_a, self.ifs_b, self.ip_b = await load_two_nodes(
            self, IP6, label="TURN fallback",
        )
        print("[TURN-TEST] setup ip_a={0} ip_b={1} ifs_a={2} ifs_b={3}".format(
            self.ip_a, self.ip_b,
            [nic.id for nic in self.ifs_a],
            [nic.id for nic in self.ifs_b],
        ))
        self.node_a = self.node_b = None
        self.turn_server = None
        self.get_infra_patcher = None

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
        """Start a local TURN server on ::1; skipTest if loopback IPv6 isn't usable.

        Loopback ::1 binding is genuinely environmental (the host either
        has working IPv6 loopback or it doesn't), so this is one of the
        few paths where skipTest is the right call.
        """
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
            port=self.turn_server.af_ports.get(IP6, self.turn_server.port), af=IP6
        )
        self.get_infra_patcher = patch(
            "p2pd.traversal.plugins.turn.main.get_infra",
            return_value=[[local_entry]],
        )
        self.get_infra_patcher.start()

    async def test_turn_fallback_returns_pipe(self):
        """With all direct plugins removed, auto_connect must relay via TURN."""
        self.node_a = await start_node_with_ifs(self.ifs_a, [self.ip_a], PORT_TURN_A_T1)
        self.node_b = await start_node_with_ifs(self.ifs_b, [self.ip_b], PORT_TURN_B_T1)
        self.assertIn(
            "turn", self.node_a.traversal.plugin_loaders,
            "turn plugin not installed",
        )
        await self._start_local_turn()

        # Remove all concurrent (non-TURN) plugins from the initiator so
        # auto_combos returns [] and falls through to TURN.
        for name in ("direct_connect", "reverse_connect", "punch"):
            self.node_a.traversal.plugin_loaders.pop(name, None)

        pipe, plugin = await asyncio.wait_for(
            auto_connect(self.node_a, self.node_b.addr_bytes, timeout=25),
            timeout=35,
        )
        log_pipe("turn_fallback_returns_pipe", pipe, plugin)

        self.assertIsNotNone(pipe, "TURN fallback must return a pipe")
        self.assertIsNotNone(plugin)
        self.assertEqual(
            type(plugin).__name__,
            "TURNPlugin",
            "Expected TURNPlugin from fallback, got {}".format(type(plugin).__name__),
        )
        try:
            await asyncio.wait_for(pipe.close(), timeout=5)
        except Exception:
            pass

    async def test_turn_plugin_in_plugin_loaders_by_default(self):
        """turn must be registered in plugin_loaders after normal node startup."""
        self.node_a = await start_node_with_ifs(self.ifs_a, [self.ip_a], PORT_TURN_A_T2)
        self.assertIn(
            "turn",
            self.node_a.traversal.plugin_loaders,
            "turn must be in plugin_loaders after startup",
        )

    async def test_turn_fallback_not_triggered_when_direct_succeeds(self):
        """When direct_connect is present it wins; TURN fallback must not run."""
        self.node_a = await start_node_with_ifs(self.ifs_a, [self.ip_a], PORT_TURN_A_T3)
        self.node_b = await start_node_with_ifs(self.ifs_b, [self.ip_b], PORT_TURN_B_T3)
        await self._start_local_turn()

        pipe, plugin = await asyncio.wait_for(
            auto_connect(self.node_a, self.node_b.addr_bytes, timeout=20),
            timeout=25,
        )
        log_pipe("not_triggered_when_direct_succeeds", pipe, plugin)

        self.assertIsNotNone(pipe)
        self.assertNotEqual(
            type(plugin).__name__,
            "TURNPlugin",
            "direct_connect should win before TURN is tried, got {}".format(
                type(plugin).__name__
            ),
        )
        try:
            await asyncio.wait_for(pipe.close(), timeout=5)
        except Exception:
            pass


if __name__ == "__main__":
    unittest.main()
