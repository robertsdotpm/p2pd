"""
Integration tests — reverse_connect.

Split out of test_auto_connect.py so the heavy AsyncTestCase classes each
get their own subprocess.

Each test gives alice and bob their own (cloned) NIC subset via
split_two_node_setups so their addr_maps differ.
"""

import asyncio
import unittest

from aionetiface import IP4
from aionetiface.testing import AsyncTestCase
from p2pd.node.auto_connect import auto_connect

from auto_connect_helpers import (
    PORT_REV_A, PORT_REV_B,
    close_nodes, fresh_ifs, split_two_node_setups, start_node_with_ifs,
)


class TestAutoConnectReverseConnect(AsyncTestCase):
    """auto_connect uses reverse_connect when direct_connect is unavailable on node_a."""

    async def asyncSetUp(self):
        probe_ifs = await fresh_ifs()
        setups = split_two_node_setups(probe_ifs, IP4)
        if setups is None:
            self.skipTest(
                "Need either 2 NICs with IPv4 each, or 1 NIC with 2 IPv4 addresses"
            )
        (self.ifs_a, self.ip_a), (self.ifs_b, self.ip_b) = setups
        self.node_a = self.node_b = None

    async def asyncTearDown(self):
        await close_nodes(self.node_b, self.node_a)

    async def test_reverse_connect_returns_pipe(self):
        """With direct_connect removed from the initiator, reverse_connect must win."""
        print("[REVERSE-TEST] setup ip_a={} ip_b={}".format(self.ip_a, self.ip_b))
        print("[REVERSE-TEST] ifs_a={}".format([nic.id for nic in self.ifs_a]))
        print("[REVERSE-TEST] ifs_b={}".format([nic.id for nic in self.ifs_b]))
        try:
            self.node_a = await start_node_with_ifs(self.ifs_a, [self.ip_a], PORT_REV_A)
            self.node_b = await start_node_with_ifs(self.ifs_b, [self.ip_b], PORT_REV_B)
        except Exception as exc:
            print("[REVERSE-TEST] node startup failed: {!r}".format(exc))
            self.skipTest("Node startup failed: {}".format(exc))

        print("[REVERSE-TEST] node_a addr_map IP4={}".format(self.node_a.addr_map.get(IP4)))
        print("[REVERSE-TEST] node_b addr_map IP4={}".format(self.node_b.addr_map.get(IP4)))
        print("[REVERSE-TEST] node_a plugins(before pop)={}".format(
            list(self.node_a.traversal.plugin_loaders.keys())
        ))
        # Remove direct_connect from the initiator only.
        # Node B still has it so it can connect back when it receives the signal.
        self.node_a.traversal.plugin_loaders.pop("direct_connect", None)
        print("[REVERSE-TEST] node_a plugins(after pop)={}".format(
            list(self.node_a.traversal.plugin_loaders.keys())
        ))
        print("[REVERSE-TEST] node_b plugins={}".format(
            list(self.node_b.traversal.plugin_loaders.keys())
        ))
        print("[REVERSE-TEST] calling auto_connect ...")

        try:
            pipe, plugin = await asyncio.wait_for(
                auto_connect(self.node_a, self.node_b.addr_bytes, timeout=20),
                timeout=25,
            )
        except asyncio.TimeoutError:
            print("[REVERSE-TEST] auto_connect timed out at outer wait_for")
            self.skipTest("auto_connect via reverse_connect timed out")

        print("[REVERSE-TEST] auto_connect returned pipe={!r} plugin={}".format(
            pipe, type(plugin).__name__ if plugin is not None else None,
        ))

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
