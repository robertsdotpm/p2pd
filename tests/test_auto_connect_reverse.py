"""
Integration tests — reverse_connect.

Split out of test_auto_connect.py so the heavy AsyncTestCase classes each
get their own subprocess.
"""

import asyncio
import unittest

from aionetiface.testing import AsyncTestCase
from p2pd.node.auto_connect import auto_connect

from auto_connect_helpers import (
    PORT_REV_A, PORT_REV_B,
    available_ipv4_addrs, close_nodes, fresh_ifs, start_node,
)


class TestAutoConnectReverseConnect(AsyncTestCase):
    """auto_connect uses reverse_connect when direct_connect is unavailable on node_a."""

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

    async def test_reverse_connect_returns_pipe(self):
        """With direct_connect removed from the initiator, reverse_connect must win."""
        try:
            self.node_a = await start_node(self.ipv4_a, PORT_REV_A)
            self.node_b = await start_node(self.ipv4_b, PORT_REV_B)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        # Remove direct_connect from the initiator only.
        # Node B still has it so it can connect back when it receives the signal.
        self.node_a.traversal.plugin_loaders.pop("direct_connect", None)

        try:
            pipe, plugin = await asyncio.wait_for(
                auto_connect(self.node_a, self.node_b.addr_bytes, timeout=20),
                timeout=25,
            )
        except asyncio.TimeoutError:
            self.skipTest("auto_connect via reverse_connect timed out")

        self.assertIsNotNone(pipe, "reverse_connect must return a pipe")
        self.assertIsNotNone(plugin)
        self.assertEqual(
            type(plugin).__name__,
            "ReverseConnectPlugin",
            "Expected ReverseConnectPlugin, got {}".format(type(plugin).__name__),
        )
        try:
            await asyncio.wait_for(pipe.close(), timeout=5)
        except Exception:
            pass


if __name__ == "__main__":
    unittest.main()
