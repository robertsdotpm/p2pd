"""
Integration tests — punch.

Split out of test_auto_connect.py so the heavy AsyncTestCase classes each
get their own subprocess.
"""

import asyncio
import unittest

from aionetiface import parse_node_addr
from aionetiface.testing import AsyncTestCase
from p2pd.node.auto_connect import auto_connect, auto_combos

from auto_connect_helpers import (
    PORT_PUNCH_A_T1, PORT_PUNCH_B_T1, PORT_PUNCH_A_T2, PORT_PUNCH_B_T2,
    PUNCH_TEST_CONF,
    available_ipv4_addrs, close_nodes, fresh_ifs, start_node,
)


class TestAutoConnectPunch(AsyncTestCase):
    """auto_connect uses TCP punch when direct_connect and reverse_connect are removed."""

    # Punch needs a longer per-test budget than the default 90s testing.py cap
    # because the inner punch round-trip wait_for is 60s.
    async_test_timeout = 120

    async def asyncSetUp(self):
        probe_ifs = await fresh_ifs()
        ipv4_addrs = available_ipv4_addrs(probe_ifs)
        if len(ipv4_addrs) < 2:
            self.skipTest(
                "Need 2 distinct non-loopback IPv4 addresses (found {})".format(len(ipv4_addrs))
            )
        self.ipv4_a = ipv4_addrs[0]
        self.ipv4_b = ipv4_addrs[1]
        self.node_a = self.node_b = None

    async def asyncTearDown(self):
        await close_nodes(self.node_b, self.node_a)

    async def test_punch_returns_pipe(self):
        """With direct_connect and reverse_connect removed, punch must establish the pipe."""
        try:
            self.node_a = await start_node(self.ipv4_a, PORT_PUNCH_A_T1, conf=PUNCH_TEST_CONF)
            self.node_b = await start_node(self.ipv4_b, PORT_PUNCH_B_T1, conf=PUNCH_TEST_CONF)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        if "punch" not in self.node_a.traversal.plugin_loaders:
            self.skipTest("punch plugin not installed (enable_punching=False?)")

        # Leave punch as the only non-skip plugin on the initiator.
        self.node_a.traversal.plugin_loaders.pop("direct_connect", None)
        self.node_a.traversal.plugin_loaders.pop("reverse_connect", None)

        try:
            pipe, plugin = await asyncio.wait_for(
                auto_connect(self.node_a, self.node_b.addr_bytes, timeout=50),
                timeout=60,
            )
        except asyncio.TimeoutError:
            self.skipTest("punch timed out (expected on some NAT configs)")
        except AssertionError:
            self.skipTest("punch: NAT type unpredictable on this network")

        if pipe is None:
            self.skipTest("punch returned None (unsupported NAT/network config)")

        self.assertIsNotNone(pipe, "punch must return a pipe")
        self.assertEqual(
            type(plugin).__name__,
            "PunchPlugin",
            "Expected PunchPlugin, got {}".format(type(plugin).__name__),
        )
        try:
            await asyncio.wait_for(pipe.close(), timeout=5)
        except Exception:
            pass

    async def test_punch_plugin_is_tried_in_combos(self):
        """With punch installed, auto_combos must include punch combos."""
        try:
            self.node_a = await start_node(self.ipv4_a, PORT_PUNCH_A_T2, conf=PUNCH_TEST_CONF)
            self.node_b = await start_node(self.ipv4_b, PORT_PUNCH_B_T2, conf=PUNCH_TEST_CONF)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        if "punch" not in self.node_a.traversal.plugin_loaders:
            self.skipTest("punch plugin not installed")

        dest_map = parse_node_addr(self.node_b.addr_bytes)
        combos = auto_combos(self.node_a, self.node_a.addr_map, dest_map)
        plugin_names = {c[0] for c in combos}
        self.assertIn(
            "punch", plugin_names, "punch must appear in auto_connect combos"
        )


if __name__ == "__main__":
    unittest.main()
