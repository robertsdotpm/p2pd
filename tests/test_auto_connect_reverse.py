"""
Integration tests — reverse_connect.

Strict on multi-NIC machines: once require_split_or_fail has handed us
two real NICs, every subsequent failure (Node startup, auto_connect
timeout, pipe is None, wrong plugin) is a real failure -- no skipTest
fallbacks.
"""

import asyncio
import unittest

from aionetiface import IP4
from aionetiface.testing import AsyncTestCase
from warpgate.node.auto_connect import auto_connect

from auto_connect_helpers import (
    PORT_REV_A, PORT_REV_B,
    close_nodes, load_two_nodes, start_node_with_ifs, isolate_plugins,
)


class TestAutoConnectReverseConnect(AsyncTestCase):
    """auto_connect uses reverse_connect when direct_connect is unavailable on node_a."""

    async def asyncSetUp(self):
        self.ifs_a, self.ip_a, self.ifs_b, self.ip_b = await load_two_nodes(
            self, IP4, label="reverse_connect",
        )
        print("[REVERSE-TEST] setup ip_a={0} ip_b={1} ifs_a={2} ifs_b={3}".format(
            self.ip_a, self.ip_b,
            [nic.id for nic in self.ifs_a],
            [nic.id for nic in self.ifs_b],
        ))
        self.node_a = self.node_b = None

    async def asyncTearDown(self):
        await close_nodes(self.node_b, self.node_a)

    async def test_reverse_connect_returns_pipe(self):
        """With direct_connect removed from the initiator, reverse_connect must win."""
        self.node_a = await start_node_with_ifs(self.ifs_a, [self.ip_a], PORT_REV_A)
        self.node_b = await start_node_with_ifs(self.ifs_b, [self.ip_b], PORT_REV_B)
        print("[REVERSE-TEST] node_a addr_map IP4={0} listen_ips={1}".format(
            self.node_a.addr_map.get(IP4), self.node_a.listen_ips,
        ))
        print("[REVERSE-TEST] node_b addr_map IP4={0} listen_ips={1}".format(
            self.node_b.addr_map.get(IP4), self.node_b.listen_ips,
        ))
        print("[REVERSE-TEST] node_a plugins(before isolate)={}".format(
            list(self.node_a.traversal.plugin_loaders.keys())
        ))
        isolate_plugins(self.node_a, "reverse_connect")
        print("[REVERSE-TEST] node_a plugins(after isolate)={}".format(
            list(self.node_a.traversal.plugin_loaders.keys())
        ))

        pipe, plugin = await asyncio.wait_for(
            auto_connect(self.node_a, self.node_b.addr_bytes, timeout=20),
            timeout=25,
        )
        print("[REVERSE-TEST] pipe={0!r} sock={1!r} plugin={2}".format(
            pipe, getattr(pipe, "sock", None),
            type(plugin).__name__ if plugin is not None else None,
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
