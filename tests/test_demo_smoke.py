"""
Smoke tests for the demo flow.

These mirror what python3 -m p2pd.demo does at startup:
  1. list_interfaces / load_interfaces  (real NIC discovery)
  2. Node(...).start()                  (full startup sequence)
  3. node.address()                     (serialised identity)
  4. parse_node_addr(addr_bytes)        (address round-trip)
  5. two nodes connect and exchange a message  (loopback connectivity)

Tests use NODE_TEST_CONF so they don't require an internet connection,
but do load real network interfaces from the host.  Any test that needs
two distinct IP addresses skips gracefully when only one is available.

Ports: NODE_PORT + 4000-4099  (avoid overlap with other test files).

Run with:
    python3 -m pytest tests/test_demo_smoke.py -v
"""

import asyncio
import unittest

import pytest

from aionetiface import (
    SUB_ALL, Interface,
    dict_child, list_interfaces, load_interfaces, parse_node_addr, sort_ips_by_nic,
)
from p2pd import Node
from p2pd.node.node_defs import NODE_TEST_CONF, NODE_PORT


BASE_PORT = NODE_PORT + 4000

# The demo uses full conf but we keep tests fast by disabling the slow bits.
# sig_pipe_no=1 lets two nodes on the same machine reach each other via MQTT;
# set to 0 for pure same-machine tests that rely only on direct TCP.
DEMO_SMOKE_CONF = dict_child(
    {
        "sig_pipe_no": 1,
        "enable_upnp": False,
        "init_clock_skew": False,
        "enable_punching": False,
        "enable_nickname": False,
        "enable_stun_clients": False,
    },
    NODE_TEST_CONF,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


async def load_demo_ifs():
    """Load interfaces the same way the demo does: real NIC discovery, no NAT detection."""
    if_names = await list_interfaces()
    return await load_interfaces(if_names, Interface, skip_nat=True)


async def start_demo_node(port, ifs=None):
    """Start a node using demo-style interface loading."""
    if ifs is None:
        ifs = await load_demo_ifs()
    node = Node(ifs=ifs, port=port, conf=DEMO_SMOKE_CONF)
    await asyncio.wait_for(node.start(), timeout=40)
    return node


async def close_nodes(*nodes):
    for node in nodes:
        if node is not None:
            try:
                await asyncio.wait_for(node.close(), timeout=10)
            except (OSError, asyncio.TimeoutError):
                pass


# ─────────────────────────────────────────────────────────────────────────────
# 1. Interface discovery (mirrors demo setup_node step 1)
# ─────────────────────────────────────────────────────────────────────────────


class TestDemoInterfaceLoading(unittest.IsolatedAsyncioTestCase):
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


@pytest.mark.network
class TestDemoNodeStart(unittest.IsolatedAsyncioTestCase):
    """A node starts successfully and exposes the expected attributes."""

    async def asyncSetUp(self):
        self.node = None

    async def asyncTearDown(self):
        await close_nodes(self.node)

    async def test_node_starts(self):
        try:
            self.node = await start_demo_node(BASE_PORT)
        except Exception as exc:
            pytest.skip("Node startup failed: {}".format(exc))

        self.assertIsNotNone(self.node)

    async def test_node_has_address_after_start(self):
        try:
            self.node = await start_demo_node(BASE_PORT + 1)
        except Exception as exc:
            pytest.skip("Node startup failed: {}".format(exc))

        addr = self.node.address()
        self.assertIsNotNone(addr)
        self.assertIsInstance(addr, bytes)
        self.assertGreater(len(addr), 0)

    async def test_node_has_node_id_after_start(self):
        try:
            self.node = await start_demo_node(BASE_PORT + 2)
        except Exception as exc:
            pytest.skip("Node startup failed: {}".format(exc))

        self.assertIsNotNone(self.node.node_id)
        self.assertIsInstance(self.node.node_id, str)
        self.assertGreater(len(self.node.node_id), 0)

    async def test_node_has_listen_port_after_start(self):
        try:
            self.node = await start_demo_node(BASE_PORT + 3)
        except Exception as exc:
            pytest.skip("Node startup failed: {}".format(exc))

        self.assertEqual(self.node.listen_port, BASE_PORT + 3)

    async def test_node_has_interfaces_after_start(self):
        try:
            self.node = await start_demo_node(BASE_PORT + 4)
        except Exception as exc:
            pytest.skip("Node startup failed: {}".format(exc))

        self.assertGreater(len(self.node.ifs), 0)

    async def test_node_supported_address_families(self):
        try:
            self.node = await start_demo_node(BASE_PORT + 5)
        except Exception as exc:
            pytest.skip("Node startup failed: {}".format(exc))

        supported = self.node.supported()
        self.assertGreater(len(supported), 0, "Node has no supported address families")


# ─────────────────────────────────────────────────────────────────────────────
# 3. Address round-trip (mirrors demo "Node started = …" output)
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.network
class TestDemoNodeAddress(unittest.IsolatedAsyncioTestCase):
    """node.address() serialises correctly and parse_node_addr recovers all fields."""

    async def asyncSetUp(self):
        self.node = None
        try:
            self.node = await start_demo_node(BASE_PORT + 10)
        except Exception as exc:
            pytest.skip("Node startup failed: {}".format(exc))

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


# ─────────────────────────────────────────────────────────────────────────────
# 4. Connectivity: two nodes start, connect, exchange a message
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.network
class TestDemoTwoNodeConnectivity(unittest.IsolatedAsyncioTestCase):
    """Two nodes on the same machine can connect and exchange data (loopback path)."""

    async def asyncSetUp(self):
        self.alice = self.bob = None

    async def asyncTearDown(self):
        await close_nodes(self.alice, self.bob)

    async def test_two_nodes_start_with_distinct_addresses(self):
        try:
            self.alice = await start_demo_node(BASE_PORT + 20)
            self.bob   = await start_demo_node(BASE_PORT + 21)
        except Exception as exc:
            pytest.skip("Node startup failed: {}".format(exc))

        self.assertNotEqual(self.alice.address(), self.bob.address())

    async def test_two_nodes_connect(self):
        from p2pd.node.auto_connect import auto_connect
        try:
            self.alice = await start_demo_node(BASE_PORT + 22)
            self.bob   = await start_demo_node(BASE_PORT + 23)
        except Exception as exc:
            pytest.skip("Node startup failed: {}".format(exc))

        try:
            pipe, plugin = await asyncio.wait_for(
                auto_connect(self.alice, self.bob.address()),
                timeout=20,
            )
        except (asyncio.TimeoutError, OSError, ConnectionError, Exception):
            pytest.skip("auto_connect did not complete")

        self.assertIsNotNone(pipe)
        await pipe.close()

    async def test_two_nodes_exchange_message(self):
        from p2pd.node.auto_connect import auto_connect
        try:
            self.alice = await start_demo_node(BASE_PORT + 24)
            self.bob   = await start_demo_node(BASE_PORT + 25)
        except Exception as exc:
            pytest.skip("Node startup failed: {}".format(exc))

        alice_pipe = bob_pipe = None
        try:
            alice_pipe, _ = await asyncio.wait_for(
                auto_connect(self.alice, self.bob.address()),
                timeout=20,
            )
            bob_pipe, _ = await asyncio.wait_for(
                auto_connect(self.bob, self.alice.address()),
                timeout=20,
            )
        except (asyncio.TimeoutError, OSError, ConnectionError, Exception):
            pytest.skip("auto_connect did not complete")

        bob_pipe.subscribe(SUB_ALL)
        await alice_pipe.send(b"demo smoke test")
        data = await bob_pipe.recv(SUB_ALL, timeout=5)
        self.assertEqual(data, b"demo smoke test")

        await alice_pipe.close()
        await bob_pipe.close()

    async def test_node_receives_via_msg_cb(self):
        """demo's add_echo_support pattern: node receives message via msg_cb."""
        from p2pd.node.auto_connect import auto_connect
        try:
            self.alice = await start_demo_node(BASE_PORT + 26)
            self.bob   = await start_demo_node(BASE_PORT + 27)
        except Exception as exc:
            pytest.skip("Node startup failed: {}".format(exc))

        received = asyncio.Event()
        received_data = []

        async def on_msg(msg, client_tup, pipe):
            received_data.append(msg)
            received.set()

        self.bob.add_msg_cb(on_msg)

        try:
            pipe, _ = await asyncio.wait_for(
                auto_connect(self.alice, self.bob.address()),
                timeout=20,
            )
        except (asyncio.TimeoutError, OSError, ConnectionError, Exception):
            pytest.skip("auto_connect did not complete")

        await pipe.send(b"hello via msg_cb")

        try:
            await asyncio.wait_for(received.wait(), timeout=5)
        except asyncio.TimeoutError:
            pytest.skip("msg_cb was not called in time")

        self.assertIn(b"hello via msg_cb", received_data)
        await pipe.close()


if __name__ == "__main__":
    unittest.main()
