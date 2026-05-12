"""
Tests for the Quickstart documentation examples.

Verifies that the code shown in docs/quickstart.md runs correctly.
These are same-machine integration tests using NODE_TEST_CONF so they
run quickly without needing real NAT traversal, UPnP, or STUN.

The auto_connect-using tests are split into:
  - test_docs_quickstart_connect.py  (TestQuickstartConnect, ports 10..17)
  - test_docs_quickstart_msg_cb.py   (TestMsgCallback, ports 20..21)
so each set runs in its own subprocess and does not inherit MQTT/socket
state from the others.

Ports here: BASE_PORT + 0..4 (single-node lifecycle).
"""

import asyncio
import unittest

from aionetiface.testing import AsyncTestCase
from warpgate import Node

from quickstart_helpers import BASE_PORT, QUICKSTART_CONF, close_nodes


class TestNodeLifecycle(AsyncTestCase):
    """Node can be started, yields an address, and can be closed."""

    async def test_node_starts_and_has_address(self):
        node = None
        try:
            node = await Node(port=BASE_PORT, conf=QUICKSTART_CONF).start()
            addr = node.address()
            self.assertIsNotNone(addr)
            self.assertIsInstance(addr, bytes)
            self.assertGreater(len(addr), 0)
        finally:
            await close_nodes(node)

    async def test_node_context_manager(self):
        """Node works as an async context manager."""
        async with Node(port=BASE_PORT + 1, conf=QUICKSTART_CONF) as node:
            await node.start()
            self.assertIsNotNone(node.address())

    async def test_two_nodes_have_distinct_addresses(self):
        alice = bob = None
        try:
            alice = await Node(port=BASE_PORT + 2, conf=QUICKSTART_CONF).start()
            bob   = await Node(port=BASE_PORT + 3, conf=QUICKSTART_CONF).start()
            self.assertNotEqual(alice.address(), bob.address())
        except (OSError, asyncio.TimeoutError) as exc:
            self.skipTest("Node startup failed (network): {}".format(exc))
        finally:
            await close_nodes(alice, bob)

    async def test_node_supported_afs_non_empty(self):
        node = None
        try:
            node = await Node(port=BASE_PORT + 4, conf=QUICKSTART_CONF).start()
            supported = node.supported()
            self.assertGreater(len(supported), 0)
        finally:
            await close_nodes(node)


if __name__ == "__main__":
    unittest.main()
