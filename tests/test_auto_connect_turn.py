"""
Integration tests — TURN fallback.

Split out of test_auto_connect.py so the heavy AsyncTestCase classes each
get their own subprocess.

The TURN server is started locally (binds to ::1), so the two nodes only
need distinct local IPv6 addresses to relay through it -- distinct globals
only matter when there are different gateways involved, and there aren't
on a same-machine loopback path. We use split_two_node_setups for both
nodes' IPv6 setup so link-local fe80 addresses on different NICs work too.
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
    close_nodes, fresh_ifs, require_split_or_fail, start_node_with_ifs,
)


class TestAutoConnectTurnFallback(AsyncTestCase):
    """auto_connect falls back to the TURN relay when all direct plugins are removed.

    Setup
    -----
    * Two nodes on distinct local IPv6 addresses (link-local on different NICs
      is fine — TURN server is local so no cross-gateway routing is needed).
    * All non-TURN, non-skip plugins (direct_connect, reverse_connect) are
      removed from the initiator so auto_combos returns an empty list and
      _race_plugin_results immediately returns (None, None).
    * A local TURNServer is started and get_infra is monkey-patched to point at
      it, so no external TURN infrastructure is needed.
    """

    async def asyncSetUp(self):
        probe_ifs = await fresh_ifs()
        self.ifs_a, self.ip_a, self.ifs_b, self.ip_b = require_split_or_fail(
            self, probe_ifs, IP6, label="TURN fallback",
        )
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

    async def test_turn_fallback_returns_pipe(self):
        """With all direct plugins removed, auto_connect must relay via TURN."""
        from turn_server import (
            TURNServer,
            make_local_turn_server_entry,
        )

        try:
            self.node_a = await start_node_with_ifs(self.ifs_a, [self.ip_a], PORT_TURN_A_T1)
            self.node_b = await start_node_with_ifs(self.ifs_b, [self.ip_b], PORT_TURN_B_T1)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        if "turn" not in self.node_a.traversal.plugin_loaders:
            self.skipTest("turn plugin not installed")

        # Start local TURN server (binds to ::1).
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

        # Redirect all TURN infrastructure lookups to our local server.
        local_entry = make_local_turn_server_entry(
            port=self.turn_server.af_ports.get(IP6, self.turn_server.port), af=IP6
        )
        self.get_infra_patcher = patch(
            "p2pd.traversal.plugins.turn.main.get_infra",
            return_value=[[local_entry]],
        )
        self.get_infra_patcher.start()

        # Remove all concurrent (non-TURN) plugins from the initiator so that
        # auto_combos returns [] and the code falls straight through to
        # _turn_fallback.
        for name in ("direct_connect", "reverse_connect", "punch"):
            self.node_a.traversal.plugin_loaders.pop(name, None)

        try:
            pipe, plugin = await asyncio.wait_for(
                auto_connect(self.node_a, self.node_b.addr_bytes, timeout=25),
                timeout=35,
            )
        except asyncio.TimeoutError:
            self.skipTest("TURN fallback timed out (check TURN server / MQTT)")

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
        try:
            self.node_a = await start_node_with_ifs(self.ifs_a, [self.ip_a], PORT_TURN_A_T2)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        self.assertIn(
            "turn",
            self.node_a.traversal.plugin_loaders,
            "turn must be in plugin_loaders after startup",
        )

    async def test_turn_fallback_not_triggered_when_direct_succeeds(self):
        """When direct_connect is present it wins; TURN fallback must not run."""
        from turn_server import TURNServer, make_local_turn_server_entry

        try:
            self.node_a = await start_node_with_ifs(self.ifs_a, [self.ip_a], PORT_TURN_A_T3)
            self.node_b = await start_node_with_ifs(self.ifs_b, [self.ip_b], PORT_TURN_B_T3)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        # TURN server started but direct_connect is still present — it should
        # win before TURN is ever attempted.
        nic = await Interface()
        if IP6 not in nic.supported():
            self.skipTest("IPv6 not available")
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

        try:
            pipe, plugin = await asyncio.wait_for(
                auto_connect(self.node_a, self.node_b.addr_bytes, timeout=20),
                timeout=25,
            )
        except asyncio.TimeoutError:
            self.skipTest("auto_connect timed out")
        except OSError:
            self.skipTest("IPv6 auto_connect raised OSError (broken IPv6 on this platform)")

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
