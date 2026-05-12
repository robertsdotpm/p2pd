"""
TestDemoNodeStart, split out of test_demo_smoke.py.

Each subtest in this class spins up a full Node via the demo's
load_interfaces -> Node().start() flow. Six of them run back-to-back
in a single unittest subprocess and on hosts with a stack of fake
adapters (Win11 with Hyper-V / WSL / loopback drivers) the FD /
socket residue from the first five Nodes has historically wedged
the sixth -- the asyncio loop ends up unable to make progress and
the runner's 300s SIGKILL kicks in.

Per CLAUDE.md "Heavy tests live in their own file": one file per
heavy AsyncTestCase so the runner's per-file subprocess gives each
test a clean Python process. Other lighter classes from the
original test_demo_smoke.py (interface loading + the address
round-trip group, which shares one Node across its asyncSetUp)
stay where they were.

Ports: BASE_PORT + 30..35 to avoid the slot test_demo_smoke uses.
"""

import unittest

from aionetiface.testing import AsyncTestCase
from warpgate import log

from demo_smoke_helpers import BASE_PORT, start_demo_node, close_nodes


# Fresh port slot so the runner can schedule both files in parallel
# without colliding with test_demo_smoke (BASE_PORT + 0..5).
NODE_START_BASE = BASE_PORT + 30


class TestDemoNodeStart(AsyncTestCase):
    """A node starts successfully and exposes the expected attributes."""

    async def asyncSetUp(self):
        self.node = None

    async def asyncTearDown(self):
        await close_nodes(self.node)

    async def test_node_starts(self):
        try:
            self.node = await start_demo_node(NODE_START_BASE)
        except Exception as exc:
            log("Node startup failed: {}".format(exc))

        self.assertIsNotNone(self.node)

    async def test_node_has_address_after_start(self):
        try:
            self.node = await start_demo_node(NODE_START_BASE + 1)
        except Exception as exc:
            log("Node startup failed: {}".format(exc))

        addr = self.node.address()
        self.assertIsNotNone(addr)
        self.assertIsInstance(addr, bytes)
        self.assertGreater(len(addr), 0)

    async def test_node_has_node_id_after_start(self):
        try:
            self.node = await start_demo_node(NODE_START_BASE + 2)
        except Exception as exc:
            log("Node startup failed: {}".format(exc))

        self.assertIsNotNone(self.node.node_id)
        self.assertIsInstance(self.node.node_id, str)
        self.assertGreater(len(self.node.node_id), 0)

    async def test_node_has_listen_port_after_start(self):
        try:
            self.node = await start_demo_node(NODE_START_BASE + 3)
        except Exception as exc:
            log("Node startup failed: {}".format(exc))

        self.assertEqual(self.node.listen_port, NODE_START_BASE + 3)

    async def test_node_has_interfaces_after_start(self):
        try:
            self.node = await start_demo_node(NODE_START_BASE + 4)
        except Exception as exc:
            log("Node startup failed: {}".format(exc))

        self.assertGreater(len(self.node.ifs), 0)

    async def test_node_supported_address_families(self):
        try:
            self.node = await start_demo_node(NODE_START_BASE + 5)
        except Exception as exc:
            log("Node startup failed: {}".format(exc))

        supported = self.node.supported()
        self.assertGreater(len(supported), 0, "Node has no supported address families")


if __name__ == "__main__":
    unittest.main()
