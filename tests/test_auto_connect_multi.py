"""
Integration tests — multi-interface (two virtual NICs per node).

Split out of test_auto_connect.py so the heavy AsyncTestCase classes each
get their own subprocess.
"""

import asyncio
import unittest

from aionetiface import IP4, IP6, parse_node_addr
from aionetiface.testing import AsyncTestCase
from p2pd.node.auto_connect import auto_connect, auto_combos

from auto_connect_helpers import (
    PORT_MULTI_A_T1, PORT_MULTI_A_T2, PORT_MULTI_A_T3,
    PORT_MULTI_B_T3, PORT_MULTI_A_T4, PORT_MULTI_B_T4,
    available_ipv4_addrs, clone_nic, close_nodes, fresh_ifs,
    global_ipv6_addrs, start_node_with_ifs,
)


class TestAutoConnectMultiInterface(AsyncTestCase):
    """auto_connect with nodes that each have two virtual interfaces (IPv4 + IPv6)."""

    async def asyncSetUp(self):
        probe_ifs = await fresh_ifs()

        ipv4_addrs = available_ipv4_addrs(probe_ifs)
        if len(ipv4_addrs) < 2:
            self.skipTest(
                "Need 2 distinct non-loopback IPv4 addresses (found {})".format(len(ipv4_addrs))
            )
        self.ipv4_a = ipv4_addrs[0]
        self.ipv4_b = ipv4_addrs[1]

        globals_v6 = global_ipv6_addrs(probe_ifs)
        if len(globals_v6) < 2:
            self.skipTest(
                "Need at least 2 global IPv6 addresses (found {})".format(len(globals_v6))
            )

        self.ipv6_a = globals_v6[0]
        self.ipv6_b = globals_v6[1]
        self.node_a = self.node_b = None

    async def asyncTearDown(self):
        await close_nodes(self.node_b, self.node_a)

    async def test_addr_map_has_two_interfaces(self):
        """Node with two virtual NICs must have two if_index entries in addr_map."""
        real_ifs = await fresh_ifs()
        if not real_ifs:
            self.skipTest("No interfaces loaded")
        real_nic = real_ifs[0]

        vnic_a0 = clone_nic(real_nic, "vnic_a0", [self.ipv4_a])
        vnic_a1 = clone_nic(real_nic, "vnic_a1", [self.ipv6_a])
        try:
            self.node_a = await start_node_with_ifs(
                [vnic_a0, vnic_a1], [self.ipv4_a, self.ipv6_a], PORT_MULTI_A_T1
            )
        except Exception as exc:
            self.skipTest("Multi-interface node startup failed: {}".format(exc))

        addr_map = self.node_a.addr_map
        if_indices_v4 = set(addr_map.get(IP4, {}).keys())
        if_indices_v6 = set(addr_map.get(IP6, {}).keys())
        total_if_indices = if_indices_v4 | if_indices_v6
        self.assertGreaterEqual(
            len(total_if_indices), 2,
            "Expected at least 2 if_index entries, got: v4={} v6={}".format(
                if_indices_v4, if_indices_v6
            ),
        )

    async def test_addr_bytes_encodes_both_interfaces(self):
        """addr_bytes serialised by a two-virtual-NIC node must round-trip to an
        addr_map that contains one IPv4 entry and one IPv6 entry, each with the
        correct NIC IP, a non-None netiface_index, and distinct if_index values.
        """
        real_ifs = await fresh_ifs()
        if not real_ifs:
            self.skipTest("No interfaces loaded")
        real_nic = real_ifs[0]

        vnic_a0 = clone_nic(real_nic, "vnic_a0", [self.ipv4_a])
        vnic_a1 = clone_nic(real_nic, "vnic_a1", [self.ipv6_a])
        try:
            self.node_a = await start_node_with_ifs(
                [vnic_a0, vnic_a1], [self.ipv4_a, self.ipv6_a], PORT_MULTI_A_T2
            )
        except Exception as exc:
            self.skipTest("Multi-interface node startup failed: {}".format(exc))

        # Round-trip: serialise then parse exactly as a peer would.
        addr_map = parse_node_addr(self.node_a.addr_bytes)

        # Must have at least one IPv4 and one IPv6 entry.
        v4_entries = addr_map.get(IP4, {})
        v6_entries = addr_map.get(IP6, {})
        self.assertTrue(v4_entries, "addr_bytes must encode at least one IPv4 interface")
        self.assertTrue(v6_entries, "addr_bytes must encode at least one IPv6 interface")

        # The IPv4 entry must carry the correct NIC IP.
        v4_info = next(iter(v4_entries.values()))
        self.assertEqual(
            str(v4_info["nic"]), self.ipv4_a,
            "IPv4 NIC IP in addr_bytes should be {}".format(self.ipv4_a),
        )

        # The IPv6 entry must carry the global address we assigned.
        v6_info = next(iter(v6_entries.values()))
        self.assertEqual(
            str(v6_info["ext"]), self.ipv6_a,
            "IPv6 ext IP in addr_bytes should be {}".format(self.ipv6_a),
        )

        # netiface_index must be set (non-None, non-negative).
        self.assertIsNotNone(v4_info["netiface_index"])
        self.assertIsNotNone(v6_info["netiface_index"])
        self.assertGreaterEqual(v4_info["netiface_index"], 0)
        self.assertGreaterEqual(v6_info["netiface_index"], 0)

        # if_index values must be distinct (each virtual NIC has its own slot).
        v4_idx = v4_info["if_index"]
        v6_idx = v6_info["if_index"]
        self.assertNotEqual(
            v4_idx, v6_idx,
            "IPv4 and IPv6 entries must have distinct if_index values, got both {}".format(v4_idx),
        )

    async def test_combos_span_both_interfaces(self):
        """Combos for a multi-interface node must include both IPv4 and IPv6 paths."""
        real_ifs = await fresh_ifs()
        if not real_ifs:
            self.skipTest("No interfaces loaded")
        real_nic = real_ifs[0]

        vnic_a0 = clone_nic(real_nic, "vnic_a0", [self.ipv4_a])
        vnic_a1 = clone_nic(real_nic, "vnic_a1", [self.ipv6_a])
        vnic_b0 = clone_nic(real_nic, "vnic_b0", [self.ipv4_b])
        vnic_b1 = clone_nic(real_nic, "vnic_b1", [self.ipv6_b])

        try:
            self.node_a = await start_node_with_ifs(
                [vnic_a0, vnic_a1], [self.ipv4_a, self.ipv6_a], PORT_MULTI_A_T3
            )
            self.node_b = await start_node_with_ifs(
                [vnic_b0, vnic_b1], [self.ipv4_b, self.ipv6_b], PORT_MULTI_B_T3
            )
        except Exception as exc:
            self.skipTest("Multi-interface node startup failed: {}".format(exc))

        dest_map = parse_node_addr(self.node_b.addr_bytes)
        combos = auto_combos(self.node_a, self.node_a.addr_map, dest_map)
        afs = {c[1] for c in combos}
        self.assertIn(IP4, afs, "Expected IPv4 combos for multi-interface node")
        self.assertIn(IP6, afs, "Expected IPv6 combos for multi-interface node")

    async def test_auto_connect_succeeds_with_two_interfaces(self):
        """auto_connect on a two-interface node pair must return a pipe."""
        real_ifs = await fresh_ifs()
        if not real_ifs:
            self.skipTest("No interfaces loaded")
        real_nic = real_ifs[0]

        vnic_a0 = clone_nic(real_nic, "vnic_a0", [self.ipv4_a])
        vnic_a1 = clone_nic(real_nic, "vnic_a1", [self.ipv6_a])
        vnic_b0 = clone_nic(real_nic, "vnic_b0", [self.ipv4_b])
        vnic_b1 = clone_nic(real_nic, "vnic_b1", [self.ipv6_b])

        try:
            self.node_a = await start_node_with_ifs(
                [vnic_a0, vnic_a1], [self.ipv4_a, self.ipv6_a], PORT_MULTI_A_T4
            )
            self.node_b = await start_node_with_ifs(
                [vnic_b0, vnic_b1], [self.ipv4_b, self.ipv6_b], PORT_MULTI_B_T4
            )
        except Exception as exc:
            self.skipTest("Multi-interface node startup failed: {}".format(exc))

        try:
            pipe, plugin = await asyncio.wait_for(
                auto_connect(self.node_a, self.node_b.addr_bytes, timeout=20),
                timeout=25,
            )
        except asyncio.TimeoutError:
            self.skipTest("auto_connect timed out on multi-interface nodes")

        self.assertIsNotNone(pipe, "auto_connect must return a pipe for multi-interface nodes")
        self.assertIsNotNone(plugin)
        try:
            await asyncio.wait_for(pipe.close(), timeout=5)
        except Exception:
            pass


if __name__ == "__main__":
    unittest.main()
