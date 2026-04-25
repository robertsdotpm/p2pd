"""
Smoke tests for the demo flow.

These mirror what python3 -m p2pd.demo does at startup:
  1. list_interfaces / load_interfaces  (real NIC discovery)
  2. Node(...).start()                  (full startup sequence)
  3. node.address()                     (serialised identity)

The two-node connectivity tests live in test_demo_two_node_connectivity.py
so they get their own subprocess (the runner runs each test_*.py file
separately), avoiding cumulative MQTT/socket state across heavy tests.

Tests use NODE_TEST_CONF so they don't require an internet connection,
but do load real network interfaces from the host. Any test that needs
two distinct IP addresses skips gracefully when only one is available.

Ports: BASE_PORT + 0..15  (the connectivity split file uses 20..27).
"""

import unittest

from aionetiface import (
    Interface, list_interfaces, parse_node_addr,
)
from aionetiface.testing import AsyncTestCase
from p2pd import log

from demo_smoke_helpers import BASE_PORT, start_demo_node, load_demo_ifs, close_nodes


# ─────────────────────────────────────────────────────────────────────────────
# 1. Interface discovery (mirrors demo setup_node step 1)
# ─────────────────────────────────────────────────────────────────────────────


class TestDemoInterfaceLoading(AsyncTestCase):
    """list_interfaces and load_interfaces work correctly on this host."""

    async def test_list_interfaces_returns_names(self):
        names = await list_interfaces()
        self.assertGreater(len(names), 0, "No network interfaces found on this host")

    async def test_load_interfaces_returns_interface_objects(self):
        ifs = await load_demo_ifs()
        self.assertGreater(len(ifs), 0, "load_interfaces returned no interfaces")
        for nic in ifs:
            self.assertIsInstance(nic, Interface)

    async def test_interfaces_have_at_least_one_address_family(self):
        ifs = await load_demo_ifs()
        for nic in ifs:
            supported = nic.supported()
            self.assertGreater(
                len(supported), 0,
                "Interface {} has no supported address families".format(nic.name),
            )


# ─────────────────────────────────────────────────────────────────────────────
# 2. Node startup (mirrors demo setup_node step 2)
# ─────────────────────────────────────────────────────────────────────────────


class TestDemoNodeStart(AsyncTestCase):
    """A node starts successfully and exposes the expected attributes."""

    async def asyncSetUp(self):
        self.node = None

    async def asyncTearDown(self):
        await close_nodes(self.node)

    async def test_node_starts(self):
        try:
            self.node = await start_demo_node(BASE_PORT)
        except Exception as exc:
            log("Node startup failed: {}".format(exc))

        self.assertIsNotNone(self.node)

    async def test_node_has_address_after_start(self):
        try:
            self.node = await start_demo_node(BASE_PORT + 1)
        except Exception as exc:
            log("Node startup failed: {}".format(exc))

        addr = self.node.address()
        self.assertIsNotNone(addr)
        self.assertIsInstance(addr, bytes)
        self.assertGreater(len(addr), 0)

    async def test_node_has_node_id_after_start(self):
        try:
            self.node = await start_demo_node(BASE_PORT + 2)
        except Exception as exc:
            log("Node startup failed: {}".format(exc))

        self.assertIsNotNone(self.node.node_id)
        self.assertIsInstance(self.node.node_id, str)
        self.assertGreater(len(self.node.node_id), 0)

    async def test_node_has_listen_port_after_start(self):
        try:
            self.node = await start_demo_node(BASE_PORT + 3)
        except Exception as exc:
            log("Node startup failed: {}".format(exc))

        self.assertEqual(self.node.listen_port, BASE_PORT + 3)

    async def test_node_has_interfaces_after_start(self):
        try:
            self.node = await start_demo_node(BASE_PORT + 4)
        except Exception as exc:
            log("Node startup failed: {}".format(exc))

        self.assertGreater(len(self.node.ifs), 0)

    async def test_node_supported_address_families(self):
        try:
            self.node = await start_demo_node(BASE_PORT + 5)
        except Exception as exc:
            log("Node startup failed: {}".format(exc))

        supported = self.node.supported()
        self.assertGreater(len(supported), 0, "Node has no supported address families")


# ─────────────────────────────────────────────────────────────────────────────
# 3. Address round-trip (mirrors demo "Node started = …" output)
# ─────────────────────────────────────────────────────────────────────────────


class TestDemoNodeAddress(AsyncTestCase):
    """node.address() serialises correctly and parse_node_addr recovers all fields."""

    async def asyncSetUp(self):
        self.node = None
        try:
            self.node = await start_demo_node(BASE_PORT + 10)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

    async def asyncTearDown(self):
        await close_nodes(self.node)

    async def test_address_bytes_is_non_empty(self):
        addr = self.node.address()
        self.assertIsNotNone(addr)
        self.assertGreater(len(addr), 0)

    async def test_address_is_parseable(self):
        addr = self.node.address()
        addr_map = parse_node_addr(addr)
        self.assertIsNotNone(addr_map)

    async def test_parsed_address_has_pub_key(self):
        addr_map = parse_node_addr(self.node.address())
        self.assertIn("pub_key_hex", addr_map)
        self.assertIsNotNone(addr_map["pub_key_hex"])
        self.assertGreater(len(addr_map["pub_key_hex"]), 0)

    async def test_parsed_address_has_machine_id(self):
        addr_map = parse_node_addr(self.node.address())
        self.assertIn("machine_id", addr_map)
        self.assertIsNotNone(addr_map["machine_id"])

    async def test_parsed_address_has_interface_info(self):
        from aionetiface import IP4, IP6
        addr_map = parse_node_addr(self.node.address())
        has_any = bool(addr_map.get(IP4)) or bool(addr_map.get(IP6))
        self.assertTrue(has_any, "Parsed address has no interface entries")

    async def test_address_round_trip_stable(self):
        addr = self.node.address()
        map1 = parse_node_addr(addr)
        map2 = parse_node_addr(addr)
        self.assertEqual(map1["pub_key_hex"], map2["pub_key_hex"])
        self.assertEqual(map1["machine_id"], map2["machine_id"])

    async def test_addr_map_matches_node_addr_map(self):
        addr_map = parse_node_addr(self.node.address())
        self.assertEqual(
            addr_map["pub_key_hex"],
            self.node.addr_map["pub_key_hex"],
        )


if __name__ == "__main__":
    unittest.main()
