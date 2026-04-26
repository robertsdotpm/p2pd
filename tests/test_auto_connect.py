"""
Unit tests for auto_connect helpers (no network).

The integration AsyncTestCase classes live in their own files so they each
get a fresh subprocess (the runner runs each test_*.py separately):

  test_auto_connect_ipv4.py    -- TestAutoConnectIPv4
  test_auto_connect_ipv6.py    -- TestAutoConnectIPv6
  test_auto_connect_reverse.py -- TestAutoConnectReverseConnect
  test_auto_connect_multi.py   -- TestAutoConnectMultiInterface
  test_auto_connect_punch.py   -- TestAutoConnectPunch
  test_auto_connect_turn.py    -- TestAutoConnectTurnFallback

This file keeps the parametric, network-free unit tests:

  TestHasValidPairVariants     -- has_valid_pair across (af, route_type, addrs)
  TestAutoComboVariants        -- combo generation across plugin/af/route dims
  TestAutoComboMultiInterface  -- multi-interface addr_maps, per-AF combo counts
"""

import unittest

from aionetiface import IP4, IP6, NIC_BIND, EXT_BIND, IPRange
from p2pd.node.auto_connect import has_valid_pair, auto_combos


# ─────────────────────────────────────────────────────────────────────────────
# Addr-map helpers (unit tests — no network)
# ─────────────────────────────────────────────────────────────────────────────


def make_fake_info(nic_ip, ext_ip, if_index=0, netiface_index=0, port=10001):
    """Build a minimal addr_map info dict as returned by parse_node_addr."""
    return {
        "nic": IPRange(nic_ip),
        "ext": IPRange(ext_ip),
        "port": port,
        "if_index": if_index,
        "netiface_index": netiface_index,
        "nat": {},
    }


def make_fake_addr_map(ip4_pairs=None, ip6_pairs=None, machine_id="machine-A"):
    """Build a minimal addr_map dict for unit tests.

    ip4_pairs / ip6_pairs: list of (nic_ip, ext_ip) tuples, one per interface
    (if_index = list position).
    """
    amap = {IP4: {}, IP6: {}, "machine_id": machine_id, "pub_key_hex": "aabb", "bytes": b""}
    if ip4_pairs:
        for i, (nic, ext) in enumerate(ip4_pairs):
            amap[IP4][i] = make_fake_info(nic, ext, if_index=i)
    if ip6_pairs:
        for i, (nic, ext) in enumerate(ip6_pairs):
            amap[IP6][i] = make_fake_info(nic, ext, if_index=i)
    return amap


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests — TestHasValidPairVariants
# ─────────────────────────────────────────────────────────────────────────────


class TestHasValidPairVariants(unittest.TestCase):
    """has_valid_pair across all (af, route_type, same/diff) combinations."""

    def check(self, src_pairs, dest_pairs, af, route_type):
        src = make_fake_addr_map(
            ip4_pairs=src_pairs if af == IP4 else None,
            ip6_pairs=src_pairs if af == IP6 else None,
            machine_id="machine-A",
        )
        dst = make_fake_addr_map(
            ip4_pairs=dest_pairs if af == IP4 else None,
            ip6_pairs=dest_pairs if af == IP6 else None,
            machine_id="machine-B",
        )
        return has_valid_pair(src, dst, af, route_type)

    # IPv4 / NIC_BIND
    def test_ip4_nic_bind_diff_nic_valid(self):
        self.assertTrue(self.check(
            [("10.0.1.76", "1.2.3.4")], [("10.0.1.100", "1.2.3.4")], IP4, NIC_BIND,
        ))

    def test_ip4_nic_bind_same_nic_invalid(self):
        self.assertFalse(self.check(
            [("10.0.1.76", "1.2.3.4")], [("10.0.1.76", "1.2.3.4")], IP4, NIC_BIND,
        ))

    # IPv4 / EXT_BIND
    def test_ip4_ext_bind_diff_ext_valid(self):
        self.assertTrue(self.check(
            [("10.0.1.76", "1.2.3.4")], [("10.0.1.100", "5.6.7.8")], IP4, EXT_BIND,
        ))

    def test_ip4_ext_bind_same_ext_invalid(self):
        self.assertFalse(self.check(
            [("10.0.1.76", "1.2.3.4")], [("10.0.1.100", "1.2.3.4")], IP4, EXT_BIND,
        ))

    # IPv6 / NIC_BIND
    def test_ip6_nic_bind_diff_nic_valid(self):
        self.assertTrue(self.check(
            [("fe80:0000:0000:0000:0000:0000:0000:0001", "2001:db8::1")],
            [("fe80:0000:0000:0000:0000:0000:0000:0002", "2001:db8::2")],
            IP6, NIC_BIND,
        ))

    def test_ip6_nic_bind_same_nic_invalid(self):
        self.assertFalse(self.check(
            [("fe80:0000:0000:0000:0000:0000:0000:0001", "2001:db8::1")],
            [("fe80:0000:0000:0000:0000:0000:0000:0001", "2001:db8::2")],
            IP6, NIC_BIND,
        ))

    # IPv6 / EXT_BIND
    def test_ip6_ext_bind_diff_ext_valid(self):
        self.assertTrue(self.check(
            [("fe80:0000:0000:0000:0000:0000:0000:0001", "2001:db8::1")],
            [("fe80:0000:0000:0000:0000:0000:0000:0002", "2001:db8::2")],
            IP6, EXT_BIND,
        ))

    def test_ip6_ext_bind_same_ext_invalid(self):
        self.assertFalse(self.check(
            [("fe80:0000:0000:0000:0000:0000:0000:0001", "2001:db8::1")],
            [("fe80:0000:0000:0000:0000:0000:0000:0002", "2001:db8::1")],
            IP6, EXT_BIND,
        ))

    # Edge cases
    def test_empty_af_returns_false(self):
        src = make_fake_addr_map()
        dst = make_fake_addr_map()
        self.assertFalse(has_valid_pair(src, dst, IP4, NIC_BIND))
        self.assertFalse(has_valid_pair(src, dst, IP6, EXT_BIND))

    def test_no_shared_if_index_optimistic_true(self):
        src = make_fake_addr_map(
            ip4_pairs=[("10.0.1.76", "1.2.3.4")], machine_id="machine-A"
        )
        dst = make_fake_addr_map(machine_id="machine-B")
        dst[IP4] = {99: make_fake_info("10.0.1.100", "1.2.3.4", if_index=99)}
        self.assertTrue(has_valid_pair(src, dst, IP4, NIC_BIND))

    # Multi-interface
    def test_multi_if_first_invalid_second_valid_returns_true(self):
        src = make_fake_addr_map(ip4_pairs=[
            ("10.0.1.76", "1.2.3.4"),
            ("192.168.1.1", "5.6.7.8"),
        ], machine_id="machine-A")
        dst = make_fake_addr_map(ip4_pairs=[
            ("10.0.1.76", "1.2.3.4"),
            ("192.168.1.2", "9.10.11.12"),
        ], machine_id="machine-B")
        self.assertTrue(has_valid_pair(src, dst, IP4, NIC_BIND))

    def test_multi_if_all_same_nic_invalid(self):
        # Cross-machine peers: matched-if_index pairs all collide on the same
        # NIC IPs, so NIC_BIND has no viable pair.
        src = make_fake_addr_map(ip4_pairs=[
            ("10.0.1.76", "1.2.3.4"),
            ("10.0.1.77", "1.2.3.4"),
        ], machine_id="machine-A")
        dst = make_fake_addr_map(ip4_pairs=[
            ("10.0.1.76", "1.2.3.4"),
            ("10.0.1.77", "1.2.3.4"),
        ], machine_id="machine-B")
        self.assertFalse(has_valid_pair(src, dst, IP4, NIC_BIND))

    def test_multi_if_ext_bind_one_pair_valid(self):
        src = make_fake_addr_map(ip4_pairs=[
            ("10.0.1.76", "1.2.3.4"),
            ("10.0.1.77", "9.0.0.1"),
        ], machine_id="machine-A")
        dst = make_fake_addr_map(ip4_pairs=[
            ("10.0.1.100", "1.2.3.4"),
            ("10.0.1.101", "9.0.0.2"),
        ], machine_id="machine-B")
        self.assertTrue(has_valid_pair(src, dst, IP4, EXT_BIND))

    def test_multi_if_dual_stack_ip4_valid_ip6_separate(self):
        src = make_fake_addr_map(
            ip4_pairs=[("10.0.1.76", "1.2.3.4")],
            ip6_pairs=[("2001:db8::1", "2001:db8::1")],
            machine_id="machine-A",
        )
        dst = make_fake_addr_map(
            ip4_pairs=[("10.0.1.100", "1.2.3.4")],
            ip6_pairs=[("2001:db8::2", "2001:db8::1")],
            machine_id="machine-B",
        )
        self.assertTrue(has_valid_pair(src, dst, IP4, NIC_BIND))
        self.assertFalse(has_valid_pair(src, dst, IP6, EXT_BIND))

    # Same-machine peers: NIC_BIND must consider cross-if_index pairs because
    # the kernel routes between any two local NICs locally. A pair that
    # doesn't line up by if_index but has distinct NIC IPs is still viable.
    def test_same_machine_cross_if_nic_bind_valid(self):
        src = make_fake_addr_map(
            ip4_pairs=[("10.0.1.76", "1.2.3.4")],
            machine_id="host-1",
        )
        # dst's only NIC is on a different subnet at if_index=1 (no if_index=0
        # match). Cross-machine logic would optimistically pass; same-machine
        # logic must positively pass via the cross-if pair.
        dst = make_fake_addr_map(machine_id="host-1")
        dst[IP4] = {1: make_fake_info("20.0.0.57", "9.10.11.12", if_index=1)}
        self.assertTrue(has_valid_pair(src, dst, IP4, NIC_BIND))


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests — TestAutoComboVariants
# ─────────────────────────────────────────────────────────────────────────────


class TestAutoComboVariants(unittest.TestCase):
    """auto_combos: correct combos for all (af, route_type, plugin, interface) dims."""

    class FakeTraversal:
        def __init__(self, names):
            self.plugin_loaders = {n: None for n in names}

    class FakeNode:
        def __init__(self, names):
            self.traversal = TestAutoComboVariants.FakeTraversal(names)

    def make_node(self, plugins=None):
        return self.FakeNode(plugins or ["direct_connect"])

    def test_turn_excluded(self):
        node = self.FakeNode(["direct_connect", "turn"])
        src = make_fake_addr_map(ip4_pairs=[("10.0.1.76", "1.2.3.4")])
        dst = make_fake_addr_map(ip4_pairs=[("10.0.1.100", "5.6.7.8")], machine_id="B")
        combos = auto_combos(node, src, dst)
        self.assertNotIn("turn", {c[0] for c in combos})
        self.assertIn("direct_connect", {c[0] for c in combos})

    def test_get_addr_and_return_addr_excluded(self):
        node = self.FakeNode(["direct_connect", "get_addr", "return_addr"])
        src = make_fake_addr_map(ip4_pairs=[("10.0.1.76", "1.2.3.4")])
        dst = make_fake_addr_map(ip4_pairs=[("10.0.1.100", "5.6.7.8")], machine_id="B")
        combos = auto_combos(node, src, dst)
        names = {c[0] for c in combos}
        self.assertNotIn("get_addr", names)
        self.assertNotIn("return_addr", names)

    def test_ip4_only_src_no_ip6_combos(self):
        node = self.make_node()
        src = make_fake_addr_map(ip4_pairs=[("10.0.1.76", "1.2.3.4")])
        dst = make_fake_addr_map(ip4_pairs=[("10.0.1.100", "5.6.7.8")], machine_id="B")
        combos = auto_combos(node, src, dst)
        self.assertNotIn(IP6, {c[1] for c in combos})

    def test_ip6_only_src_no_ip4_combos(self):
        node = self.make_node()
        src = make_fake_addr_map(ip6_pairs=[("2001:db8::1", "2001:db8::1")])
        dst = make_fake_addr_map(ip6_pairs=[("2001:db8::2", "2001:db8::2")], machine_id="B")
        combos = auto_combos(node, src, dst)
        self.assertNotIn(IP4, {c[1] for c in combos})

    def test_dual_stack_both_afs_present(self):
        node = self.make_node()
        src = make_fake_addr_map(
            ip4_pairs=[("10.0.1.76", "1.2.3.4")],
            ip6_pairs=[("2001:db8::1", "2001:db8::1")],
        )
        dst = make_fake_addr_map(
            ip4_pairs=[("10.0.1.100", "5.6.7.8")],
            ip6_pairs=[("2001:db8::2", "2001:db8::2")],
            machine_id="B",
        )
        combos = auto_combos(node, src, dst)
        afs = {c[1] for c in combos}
        self.assertIn(IP4, afs)
        self.assertIn(IP6, afs)

    def test_same_ext_excludes_ext_bind(self):
        node = self.make_node()
        src = make_fake_addr_map(ip4_pairs=[("10.0.1.76", "1.2.3.4")])
        dst = make_fake_addr_map(ip4_pairs=[("10.0.1.100", "1.2.3.4")], machine_id="B")
        combos = auto_combos(node, src, dst)
        route_types = {c[2] for c in combos}
        self.assertNotIn(EXT_BIND, route_types)
        self.assertIn(NIC_BIND, route_types)

    def test_diff_ext_includes_both_route_types(self):
        node = self.make_node()
        src = make_fake_addr_map(ip4_pairs=[("10.0.1.76", "1.2.3.4")])
        dst = make_fake_addr_map(ip4_pairs=[("10.0.1.100", "5.6.7.8")], machine_id="B")
        combos = auto_combos(node, src, dst)
        route_types = {c[2] for c in combos}
        self.assertIn(NIC_BIND, route_types)
        self.assertIn(EXT_BIND, route_types)

    def test_nic_bind_listed_before_ext_bind(self):
        node = self.make_node()
        src = make_fake_addr_map(ip4_pairs=[("10.0.1.76", "1.2.3.4")])
        dst = make_fake_addr_map(ip4_pairs=[("10.0.1.100", "5.6.7.8")], machine_id="B")
        combos = auto_combos(node, src, dst)
        route_types = [c[2] for c in combos]
        self.assertLess(route_types.index(NIC_BIND), route_types.index(EXT_BIND))

    def test_each_plugin_present_once_per_af_route_type(self):
        node = self.FakeNode(["direct_connect", "punch"])
        src = make_fake_addr_map(ip4_pairs=[("10.0.1.76", "1.2.3.4")])
        dst = make_fake_addr_map(ip4_pairs=[("10.0.1.100", "5.6.7.8")], machine_id="B")
        combos = auto_combos(node, src, dst)
        names = [c[0] for c in combos]
        self.assertEqual(names.count("direct_connect"), names.count("punch"))
        self.assertGreater(names.count("direct_connect"), 0)

    def test_ip6_ext_bind_excluded_same_ext(self):
        node = self.make_node()
        src = make_fake_addr_map(ip6_pairs=[("fe80::1", "2001:db8::1")])
        dst = make_fake_addr_map(ip6_pairs=[("fe80::2", "2001:db8::1")], machine_id="B")
        combos = auto_combos(node, src, dst)
        route_types = {c[2] for c in combos}
        self.assertNotIn(EXT_BIND, route_types)
        self.assertIn(NIC_BIND, route_types)

    def test_ip6_ext_bind_included_diff_ext(self):
        node = self.make_node()
        src = make_fake_addr_map(ip6_pairs=[("2001:db8::1", "2001:db8::1")])
        dst = make_fake_addr_map(ip6_pairs=[("2001:db8::2", "2001:db8::2")], machine_id="B")
        combos = auto_combos(node, src, dst)
        route_types = {c[2] for c in combos}
        self.assertIn(EXT_BIND, route_types)


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests — TestAutoComboMultiInterface
# ─────────────────────────────────────────────────────────────────────────────


class TestAutoComboMultiInterface(unittest.TestCase):
    """auto_combos with multiple if_index entries in the addr_map."""

    class FakeNode:
        class FakeTraversal:
            def __init__(self, names):
                self.plugin_loaders = {n: None for n in names}
        def __init__(self, names):
            self.traversal = TestAutoComboMultiInterface.FakeNode.FakeTraversal(names)

    def make_node(self, plugins=None):
        return self.FakeNode(plugins or ["direct_connect"])

    def test_dual_stack_generates_more_combos_than_ipv4_only(self):
        node = self.make_node()

        src_v4 = make_fake_addr_map(ip4_pairs=[("10.0.1.76", "1.2.3.4")])
        dst_v4 = make_fake_addr_map(ip4_pairs=[("10.0.1.100", "5.6.7.8")], machine_id="B")
        combos_v4 = auto_combos(node, src_v4, dst_v4)

        src_dual = make_fake_addr_map(
            ip4_pairs=[("10.0.1.76", "1.2.3.4")],
            ip6_pairs=[("2001:db8::1", "2001:db8::1")],
        )
        dst_dual = make_fake_addr_map(
            ip4_pairs=[("10.0.1.100", "5.6.7.8")],
            ip6_pairs=[("2001:db8::2", "2001:db8::2")],
            machine_id="B",
        )
        combos_dual = auto_combos(node, src_dual, dst_dual)

        self.assertGreater(len(combos_dual), len(combos_v4))

    def test_dual_stack_multi_interface_combos_span_both_afs(self):
        node = self.make_node()
        src = make_fake_addr_map(
            ip4_pairs=[("10.0.1.76", "1.2.3.4")],
            ip6_pairs=[("2001:db8::1", "2001:db8::1")],
        )
        dst = make_fake_addr_map(
            ip4_pairs=[("10.0.1.100", "5.6.7.8")],
            ip6_pairs=[("2001:db8::2", "2001:db8::2")],
            machine_id="B",
        )
        combos = auto_combos(node, src, dst)
        afs = {c[1] for c in combos}
        self.assertIn(IP4, afs)
        self.assertIn(IP6, afs)

    def test_invalid_if_index_pair_does_not_suppress_valid_one(self):
        node = self.make_node()
        src = make_fake_addr_map(ip4_pairs=[
            ("10.0.1.76", "1.2.3.4"),
            ("172.16.0.1", "9.9.9.9"),
        ])
        dst = make_fake_addr_map(ip4_pairs=[
            ("10.0.1.76", "1.2.3.4"),
            ("172.16.0.2", "8.8.8.8"),
        ], machine_id="B")
        combos = auto_combos(node, src, dst)
        self.assertGreater(len(combos), 0)

    def test_multi_plugin_multi_interface_count(self):
        node = self.FakeNode(["direct_connect", "punch"])
        src = make_fake_addr_map(
            ip4_pairs=[("10.0.1.76", "1.2.3.4")],
            ip6_pairs=[("2001:db8::1", "2001:db8::1")],
        )
        dst = make_fake_addr_map(
            ip4_pairs=[("10.0.1.100", "5.6.7.8")],
            ip6_pairs=[("2001:db8::2", "2001:db8::2")],
            machine_id="B",
        )
        combos = auto_combos(node, src, dst)
        self.assertGreaterEqual(len(combos), 4)

    def test_all_interfaces_invalid_returns_empty(self):
        node = self.make_node()
        src = make_fake_addr_map(ip4_pairs=[
            ("10.0.1.76", "1.2.3.4"),
            ("10.0.1.77", "1.2.3.4"),
        ])
        dst = make_fake_addr_map(ip4_pairs=[
            ("10.0.1.76", "1.2.3.4"),
            ("10.0.1.77", "1.2.3.4"),
        ], machine_id="B")
        combos = auto_combos(node, src, dst)
        self.assertEqual(len(combos), 0)


if __name__ == "__main__":
    unittest.main()
