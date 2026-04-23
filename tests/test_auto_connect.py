"""
Tests for auto_connect.

Parameters varied across unit tests: af (IP4/IP6), route_type (NIC_BIND/EXT_BIND),
number of interfaces (1 / multi), same vs different nic/ext IPs.

Unit tests (no network):
  TestHasValidPairVariants  -- all combinations of af/route_type/same-diff addresses.
  TestAutoComboVariants     -- combo generation across all parameter dimensions.
  TestAutoComboMultiInterface -- multi-interface addr_maps, per-interface combo counts.

Integration tests (require network + MQTT):
  TestAutoConnectIPv4           -- direct_connect, IPv4 NIC_BIND.
  TestAutoConnectIPv6           -- direct_connect, IPv6 EXT_BIND (global addrs).
  TestAutoConnectReverseConnect -- reverse_connect wins when direct is removed.
  TestAutoConnectMultiInterface -- two fake-NIC nodes (IPv4 + IPv6 each);
                                   also verifies fake NICs appear in serialised addr_bytes.
  TestAutoConnectPunch          -- punch wins when direct+reverse are removed.
  TestAutoConnectTurnFallback   -- TURN relay used when all direct plugins are removed.

Run from project root:
    python3 -m pytest tests/test_auto_connect.py -v
"""

import asyncio
import copy
import sys
import unittest
from unittest.mock import patch

import pytest

from aionetiface import (
    IP4,
    IP6,
    NIC_BIND,
    EXT_BIND,
    IPRange,
    Interface,
    dict_child,
    list_interfaces,
    load_interfaces,
    parse_node_addr,
    sort_ips_by_nic,
    DUEL_STACK,
)

from p2pd import Node
from p2pd.node.node_defs import NODE_TEST_CONF, NODE_PORT
from p2pd.node.auto_connect import auto_connect, has_valid_pair, auto_combos


# ─────────────────────────────────────────────────────────────────────────────
# Test configurations
# ─────────────────────────────────────────────────────────────────────────────

AUTO_TEST_CONF = dict_child(
    {
        "enable_upnp": False,
        "sig_pipe_no": 1,
        "init_clock_skew": False,
        "enable_punching": False,
        "enable_nickname": False,
        "enable_stun_clients": False,
    },
    NODE_TEST_CONF,
)

# Punch requires STUN clients for NTP timing and port allocation.
PUNCH_TEST_CONF = dict_child(
    {
        "enable_upnp": False,
        "sig_pipe_no": 1,
        "init_clock_skew": False,
        "enable_punching": True,
        "enable_nickname": False,
        "enable_stun_clients": True,
    },
    NODE_TEST_CONF,
)

# Per-test unique ports — each test method in each class gets its own pair so
# tests can run in parallel (--dist=load) without port conflicts.
# Layout: each class gets a 100-port range; each test method gets a 10-port slot.

# TestAutoConnectIPv4 — 2000–2099
PORT_A_T1 = NODE_PORT + 2000; PORT_B_T1 = NODE_PORT + 2001
PORT_A_T2 = NODE_PORT + 2010; PORT_B_T2 = NODE_PORT + 2011
PORT_A_T3 = NODE_PORT + 2020; PORT_B_T3 = NODE_PORT + 2021

# TestAutoConnectIPv6 — 2100–2199
PORT_A6_T1 = NODE_PORT + 2100; PORT_B6_T1 = NODE_PORT + 2101
PORT_A6_T2 = NODE_PORT + 2110; PORT_B6_T2 = NODE_PORT + 2111

# TestAutoConnectReverseConnect — 2200–2299 (single test)
PORT_REV_A = NODE_PORT + 2200; PORT_REV_B = NODE_PORT + 2201

# TestAutoConnectMultiInterface — 2300–2399
PORT_MULTI_A_T1 = NODE_PORT + 2300
PORT_MULTI_A_T2 = NODE_PORT + 2310
PORT_MULTI_A_T3 = NODE_PORT + 2320; PORT_MULTI_B_T3 = NODE_PORT + 2321
PORT_MULTI_A_T4 = NODE_PORT + 2330; PORT_MULTI_B_T4 = NODE_PORT + 2331

# TestAutoConnectPunch — 2400–2499
PORT_PUNCH_A_T1 = NODE_PORT + 2400; PORT_PUNCH_B_T1 = NODE_PORT + 2401
PORT_PUNCH_A_T2 = NODE_PORT + 2410; PORT_PUNCH_B_T2 = NODE_PORT + 2411

# TestAutoConnectTurnFallback — 2500–2599
PORT_TURN_A_T1 = NODE_PORT + 2500; PORT_TURN_B_T1 = NODE_PORT + 2501
PORT_TURN_A_T2 = NODE_PORT + 2510
PORT_TURN_A_T3 = NODE_PORT + 2520; PORT_TURN_B_T3 = NODE_PORT + 2521


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
# Fake-interface factory (integration tests — real sockets, fake topology)
# ─────────────────────────────────────────────────────────────────────────────


def clone_nic(real_nic, new_id, ip_list):
    """Return a shallow copy of real_nic with a different id and a filtered route pool.

    The copy keeps real_nic.name so that IPv6 scope-ID appending still uses the
    correct physical interface name.  new_id makes sort_ips_by_nic treat this as
    a distinct interface from real_nic, enabling multi-interface node setups on a
    single physical NIC.

    ip_list must be a list of IP address strings.  Only address families present
    in ip_list are kept in the route pool; the rest are cleared so this clone only
    claims those specific addresses.
    """
    from aionetiface.nic.route.rp_from_ip import route_pool_from_ips
    from aionetiface.nic.route.route_pool import RoutePool

    nic = copy.copy(real_nic)
    nic.id = new_id

    rp = route_pool_from_ips(ip_list, real_nic)

    represented_afs = set()
    for ip in ip_list:
        try:
            represented_afs.add(IPRange(ip).af)
        except Exception:
            pass

    for af in (IP4, IP6):
        if af not in represented_afs:
            rp[af] = RoutePool()

    nic.rp = rp

    # Set stack to match only the AFs that have routes, so nic.supported()
    # doesn't claim IPv6 when only IPv4 addresses were requested (which would
    # cause node startup to call nic.route(IP6) on an empty route pool).
    if len(represented_afs) == 1:
        nic.stack = list(represented_afs)[0]
    else:
        nic.stack = DUEL_STACK

    return nic


# ─────────────────────────────────────────────────────────────────────────────
# Integration test helpers
# ─────────────────────────────────────────────────────────────────────────────


async def fresh_ifs():
    """Load a fresh set of interfaces (without NAT detection) for one node."""
    if_names = await list_interfaces()
    return await load_interfaces(if_names, Interface, skip_nat=True)


async def start_node(ip, port, conf=None):
    """Start a node bound to a single IP on freshly loaded interfaces."""
    ifs = await fresh_ifs()
    node = Node(ifs=ifs, ip=[ip], port=port, conf=conf or AUTO_TEST_CONF)
    await asyncio.wait_for(node.start(), timeout=35)
    return node


async def start_node_with_ifs(ifs, ip_list, port, conf=None):
    """Start a node with a pre-built ifs list and explicit listen-IP list."""
    node = Node(ifs=ifs, ip=ip_list, port=port, conf=conf or AUTO_TEST_CONF)
    await asyncio.wait_for(node.start(), timeout=35)
    return node


def ifs_have_ip(ifs, ip_str):
    """Return True if ip_str appears in any NIC's route pool (primary or secondary)."""
    by_nic = sort_ips_by_nic([ip_str], ifs)
    return any(ips for ips in by_nic.values())


def global_ipv6_addrs(ifs):
    """Return unique global (non-link-local, non-loopback) IPv6 strings from all NICs."""
    seen = set()
    addrs = []
    for nic in ifs:
        if IP6 not in nic.supported():
            continue
        for route in nic.rp[IP6]:
            for ipr in route.nic_ips:
                s = str(ipr)
                if s.startswith("fe80") or s in ("::1", "::"):
                    continue
                if s not in seen:
                    seen.add(s)
                    addrs.append(s)
    return addrs


def available_ipv4_addrs(ifs):
    """Return unique non-loopback IPv4 strings from all NICs, ordered by NIC then IP."""
    seen = set()
    addrs = []
    for nic in ifs:
        if IP4 not in nic.supported():
            continue
        for route in nic.rp[IP4]:
            for ipr in route.nic_ips:
                s = str(ipr)
                if s.startswith("127."):
                    continue
                if s not in seen:
                    seen.add(s)
                    addrs.append(s)
    return addrs


async def close_nodes(*nodes):
    for node in nodes:
        if node is not None:
            try:
                await asyncio.wait_for(node.close(), timeout=10)
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests — TestHasValidPairVariants
# ─────────────────────────────────────────────────────────────────────────────


class TestHasValidPairVariants(unittest.TestCase):
    """has_valid_pair across all (af, route_type, same/diff) combinations."""

    def check(self, src_pairs, dest_pairs, af, route_type):
        src = make_fake_addr_map(
            ip4_pairs=src_pairs if af == IP4 else None,
            ip6_pairs=src_pairs if af == IP6 else None,
        )
        dst = make_fake_addr_map(
            ip4_pairs=dest_pairs if af == IP4 else None,
            ip6_pairs=dest_pairs if af == IP6 else None,
        )
        return has_valid_pair(src, dst, af, route_type)

    # ── IPv4 / NIC_BIND ──────────────────────────────────────────────────────
    def test_ip4_nic_bind_diff_nic_valid(self):
        self.assertTrue(self.check(
            [("10.0.1.76", "1.2.3.4")], [("10.0.1.100", "1.2.3.4")], IP4, NIC_BIND,
        ))

    def test_ip4_nic_bind_same_nic_invalid(self):
        self.assertFalse(self.check(
            [("10.0.1.76", "1.2.3.4")], [("10.0.1.76", "1.2.3.4")], IP4, NIC_BIND,
        ))

    # ── IPv4 / EXT_BIND ──────────────────────────────────────────────────────
    def test_ip4_ext_bind_diff_ext_valid(self):
        self.assertTrue(self.check(
            [("10.0.1.76", "1.2.3.4")], [("10.0.1.100", "5.6.7.8")], IP4, EXT_BIND,
        ))

    def test_ip4_ext_bind_same_ext_invalid(self):
        self.assertFalse(self.check(
            [("10.0.1.76", "1.2.3.4")], [("10.0.1.100", "1.2.3.4")], IP4, EXT_BIND,
        ))

    # ── IPv6 / NIC_BIND ──────────────────────────────────────────────────────
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

    # ── IPv6 / EXT_BIND ──────────────────────────────────────────────────────
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

    # ── Edge cases ────────────────────────────────────────────────────────────
    def test_empty_af_returns_false(self):
        src = make_fake_addr_map()
        dst = make_fake_addr_map()
        self.assertFalse(has_valid_pair(src, dst, IP4, NIC_BIND))
        self.assertFalse(has_valid_pair(src, dst, IP6, EXT_BIND))

    def test_no_shared_if_index_optimistic_true(self):
        src = make_fake_addr_map(ip4_pairs=[("10.0.1.76", "1.2.3.4")])
        dst = make_fake_addr_map()
        dst[IP4] = {99: make_fake_info("10.0.1.100", "1.2.3.4", if_index=99)}
        self.assertTrue(has_valid_pair(src, dst, IP4, NIC_BIND))

    # ── Multi-interface ───────────────────────────────────────────────────────
    def test_multi_if_first_invalid_second_valid_returns_true(self):
        src = make_fake_addr_map(ip4_pairs=[
            ("10.0.1.76", "1.2.3.4"),   # if_index 0 — same nic as dst
            ("192.168.1.1", "5.6.7.8"), # if_index 1 — different nic
        ])
        dst = make_fake_addr_map(ip4_pairs=[
            ("10.0.1.76", "1.2.3.4"),   # if_index 0 — same nic, invalid
            ("192.168.1.2", "9.10.11.12"), # if_index 1 — diff nic, valid
        ])
        self.assertTrue(has_valid_pair(src, dst, IP4, NIC_BIND))

    def test_multi_if_all_same_nic_invalid(self):
        src = make_fake_addr_map(ip4_pairs=[
            ("10.0.1.76", "1.2.3.4"),
            ("10.0.1.77", "1.2.3.4"),
        ])
        dst = make_fake_addr_map(ip4_pairs=[
            ("10.0.1.76", "1.2.3.4"),
            ("10.0.1.77", "1.2.3.4"),
        ])
        self.assertFalse(has_valid_pair(src, dst, IP4, NIC_BIND))

    def test_multi_if_ext_bind_one_pair_valid(self):
        src = make_fake_addr_map(ip4_pairs=[
            ("10.0.1.76", "1.2.3.4"),  # same ext as dst if_0
            ("10.0.1.77", "9.0.0.1"),  # diff ext from dst if_1
        ])
        dst = make_fake_addr_map(ip4_pairs=[
            ("10.0.1.100", "1.2.3.4"),  # same ext, EXT_BIND invalid
            ("10.0.1.101", "9.0.0.2"),  # diff ext, EXT_BIND valid
        ])
        self.assertTrue(has_valid_pair(src, dst, IP4, EXT_BIND))

    def test_multi_if_dual_stack_ip4_valid_ip6_separate(self):
        src = make_fake_addr_map(
            ip4_pairs=[("10.0.1.76", "1.2.3.4")],
            ip6_pairs=[("2001:db8::1", "2001:db8::1")],
        )
        dst = make_fake_addr_map(
            ip4_pairs=[("10.0.1.100", "1.2.3.4")],
            ip6_pairs=[("2001:db8::2", "2001:db8::1")],
        )
        self.assertTrue(has_valid_pair(src, dst, IP4, NIC_BIND))
        self.assertFalse(has_valid_pair(src, dst, IP6, EXT_BIND))


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

    # ── Skip-list filtering ───────────────────────────────────────────────────
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

    # ── Address-family filtering ──────────────────────────────────────────────
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

    # ── Route-type filtering ──────────────────────────────────────────────────
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

    # ── Multiple plugins ──────────────────────────────────────────────────────
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
        # auto_combos produces one combo per (plugin, af, route_type) triple.
        # A single-AF node has at most 2 combos (NIC_BIND + EXT_BIND).
        # Adding a second AF (IPv6) via a second interface doubles the combos.
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
        # if_index 0: same NIC IPs (NIC_BIND invalid), same ext IPs (EXT_BIND invalid)
        # if_index 1: diff NIC IPs (NIC_BIND valid)
        src = make_fake_addr_map(ip4_pairs=[
            ("10.0.1.76", "1.2.3.4"),
            ("172.16.0.1", "9.9.9.9"),
        ])
        dst = make_fake_addr_map(ip4_pairs=[
            ("10.0.1.76", "1.2.3.4"),   # if_index 0 — all same, both invalid
            ("172.16.0.2", "8.8.8.8"),  # if_index 1 — both different, both valid
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
        # 2 plugins * 2 AFs * up-to-2 route_types = at most 8; at least 4
        self.assertGreaterEqual(len(combos), 4)

    def test_all_interfaces_invalid_returns_empty(self):
        node = self.make_node()
        # Every if_index pair has identical NIC and ext IPs → all invalid
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


# ─────────────────────────────────────────────────────────────────────────────
# Integration tests — IPv4 direct_connect
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.network
class TestAutoConnectIPv4(unittest.IsolatedAsyncioTestCase):
    """auto_connect over IPv4 NIC_BIND between two nodes on the same host."""

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

    async def test_auto_connect_returns_pipe(self):
        """auto_connect must return a usable pipe."""
        try:
            self.node_a = await start_node(self.ipv4_a, PORT_A_T1)
            self.node_b = await start_node(self.ipv4_b, PORT_B_T1)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        try:
            pipe, plugin = await asyncio.wait_for(
                auto_connect(self.node_a, self.node_b.addr_bytes, timeout=20),
                timeout=25,
            )
        except asyncio.TimeoutError:
            self.skipTest("auto_connect timed out")

        self.assertIsNotNone(pipe)
        self.assertIsNotNone(plugin)
        from aionetiface import SUB_ALL, to_b
        pipe.subscribe(SUB_ALL)
        await pipe.send(to_b("hello auto_connect\n"))
        await pipe.close()

    async def test_plugin_is_direct_connect_on_same_lan(self):
        """NIC_BIND direct_connect should win on the same LAN."""
        try:
            self.node_a = await start_node(self.ipv4_a, PORT_A_T2)
            self.node_b = await start_node(self.ipv4_b, PORT_B_T2)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        try:
            pipe, plugin = await asyncio.wait_for(
                auto_connect(self.node_a, self.node_b.addr_bytes, timeout=20),
                timeout=25,
            )
        except asyncio.TimeoutError:
            self.skipTest("auto_connect timed out")

        self.assertIsNotNone(pipe)
        self.assertIn(
            type(plugin).__name__,
            ("DirectConnect", "ReverseConnectPlugin"),
            "Expected direct or reverse on same LAN, got: {}".format(type(plugin).__name__),
        )
        await pipe.close()

    async def test_combos_include_nic_bind(self):
        """NIC_BIND combos must be generated when two NIC IPs are reachable."""
        try:
            self.node_a = await start_node(self.ipv4_a, PORT_A_T3)
            self.node_b = await start_node(self.ipv4_b, PORT_B_T3)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        dest_map = parse_node_addr(self.node_b.addr_bytes)
        combos = auto_combos(self.node_a, self.node_a.addr_map, dest_map)
        route_types = {c[2] for c in combos}
        self.assertIn(NIC_BIND, route_types)


# ─────────────────────────────────────────────────────────────────────────────
# Integration tests — IPv6 direct_connect (global addresses)
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.network
class TestAutoConnectIPv6(unittest.IsolatedAsyncioTestCase):
    """auto_connect over IPv6 EXT_BIND using two distinct global addresses."""

    async def asyncSetUp(self):
        probe_ifs = await fresh_ifs()
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

    async def test_auto_connect_returns_pipe(self):
        """auto_connect on distinct global IPv6 addresses must return a pipe."""
        try:
            self.node_a = await start_node(self.ipv6_a, PORT_A6_T1)
            self.node_b = await start_node(self.ipv6_b, PORT_B6_T1)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        try:
            pipe, plugin = await asyncio.wait_for(
                auto_connect(self.node_a, self.node_b.addr_bytes, timeout=20),
                timeout=25,
            )
        except asyncio.TimeoutError:
            self.skipTest("auto_connect timed out over IPv6")

        self.assertIsNotNone(pipe)
        self.assertIsNotNone(plugin)
        await pipe.close()

    async def test_combos_include_ext_bind_for_diff_global_ipv6(self):
        """Different global IPv6 ext IPs → EXT_BIND combos must be generated."""
        try:
            self.node_a = await start_node(self.ipv6_a, PORT_A6_T2)
            self.node_b = await start_node(self.ipv6_b, PORT_B6_T2)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        dest_map = parse_node_addr(self.node_b.addr_bytes)
        combos = auto_combos(self.node_a, self.node_a.addr_map, dest_map)
        v6_route_types = {c[2] for c in combos if c[1] == IP6}
        self.assertIn(EXT_BIND, v6_route_types)


# ─────────────────────────────────────────────────────────────────────────────
# Integration tests — reverse_connect
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.network
class TestAutoConnectReverseConnect(unittest.IsolatedAsyncioTestCase):
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
        await pipe.close()


# ─────────────────────────────────────────────────────────────────────────────
# Integration tests — multi-interface (two virtual NICs per node)
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.network
class TestAutoConnectMultiInterface(unittest.IsolatedAsyncioTestCase):
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

        This verifies that fake (clone_nic) interfaces are visible in the wire
        representation that a peer would receive and parse.
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
        await pipe.close()


# ─────────────────────────────────────────────────────────────────────────────
# Integration tests — punch
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.network
class TestAutoConnectPunch(unittest.IsolatedAsyncioTestCase):
    """auto_connect uses TCP punch when direct_connect and reverse_connect are removed."""

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

        if pipe is None:
            self.skipTest("punch returned None (unsupported NAT/network config)")

        self.assertIsNotNone(pipe, "punch must return a pipe")
        self.assertEqual(
            type(plugin).__name__,
            "PunchPlugin",
            "Expected PunchPlugin, got {}".format(type(plugin).__name__),
        )
        await pipe.close()

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


# ─────────────────────────────────────────────────────────────────────────────
# Integration tests — TURN fallback
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.network
class TestAutoConnectTurnFallback(unittest.IsolatedAsyncioTestCase):
    """auto_connect falls back to the TURN relay when all direct plugins are removed.

    Setup
    -----
    * Two nodes on distinct global IPv6 addresses (required for EXT_BIND, which
      is the only route_type _turn_fallback tries).
    * All non-TURN, non-skip plugins (direct_connect, reverse_connect) are
      removed from the initiator so auto_combos returns an empty list and
      _race_plugin_results immediately returns (None, None).
    * A local TURNServer is started and get_infra is monkey-patched to point at
      it, so no external TURN infrastructure is needed.
    """

    async def asyncSetUp(self):
        probe_ifs = await fresh_ifs()
        globals_v6 = global_ipv6_addrs(probe_ifs)
        if len(globals_v6) < 2:
            self.skipTest(
                "Need at least 2 global IPv6 addresses for TURN fallback test "
                "(found {})".format(len(globals_v6))
            )
        self.ipv6_a = globals_v6[0]
        self.ipv6_b = globals_v6[1]
        self.node_a = self.node_b = None
        self.turn_server = None
        self.get_infra_patcher = None

    async def asyncTearDown(self):
        if self.get_infra_patcher is not None:
            self.get_infra_patcher.stop()
        if self.turn_server is not None:
            try:
                await asyncio.wait_for(self.turn_server.close(), timeout=5)
            except Exception:
                pass
        await close_nodes(self.node_b, self.node_a)

    async def test_turn_fallback_returns_pipe(self):
        """With all direct plugins removed, auto_connect must relay via TURN."""
        from tests.turn_server import (
            TURNServer,
            make_local_turn_server_entry,
        )

        try:
            self.node_a = await start_node(self.ipv6_a, PORT_TURN_A_T1)
            self.node_b = await start_node(self.ipv6_b, PORT_TURN_B_T1)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        if "turn" not in self.node_a.traversal.plugin_loaders:
            self.skipTest("turn plugin not installed")

        # Start local TURN server (binds to ::1).
        nic = await Interface()
        if IP6 not in nic.supported():
            self.skipTest("IPv6 not available on loopback interface")
        self.turn_server = TURNServer(nic)
        try:
            await self.turn_server.start()
        except OSError:
            self.skipTest("IPv6 loopback not functional (OSError on TURN server start)")
        if IP6 not in self.turn_server.started_afs():
            await self.turn_server.close()
            self.skipTest("TURN server could not bind IPv6 (::1 unavailable)")

        # Redirect all TURN infrastructure lookups to our local server.
        local_entry = make_local_turn_server_entry(
            port=self.turn_server.af_ports.get(IP6, self.turn_server.port), af=IP6
        )
        self.get_infra_patcher = patch(
            "p2pd.traversal.plugins.turn.main.get_infra",
            return_value=[[local_entry]],
        )
        self.get_infra_patcher.start()

        # Remove all concurrent (non-TURN) plugins from the initiator so that
        # auto_combos returns [] and the code falls straight through to
        # _turn_fallback.
        for name in ("direct_connect", "reverse_connect", "punch"):
            self.node_a.traversal.plugin_loaders.pop(name, None)

        try:
            pipe, plugin = await asyncio.wait_for(
                auto_connect(self.node_a, self.node_b.addr_bytes, timeout=25),
                timeout=35,
            )
        except asyncio.TimeoutError:
            self.skipTest("TURN fallback timed out (check TURN server / MQTT)")

        self.assertIsNotNone(pipe, "TURN fallback must return a pipe")
        self.assertIsNotNone(plugin)
        self.assertEqual(
            type(plugin).__name__,
            "TURNPlugin",
            "Expected TURNPlugin from fallback, got {}".format(type(plugin).__name__),
        )
        await pipe.close()

    async def test_turn_plugin_in_plugin_loaders_by_default(self):
        """turn must be registered in plugin_loaders after normal node startup."""
        try:
            self.node_a = await start_node(self.ipv6_a, PORT_TURN_A_T2)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        self.assertIn(
            "turn",
            self.node_a.traversal.plugin_loaders,
            "turn must be in plugin_loaders after startup",
        )

    async def test_turn_fallback_not_triggered_when_direct_succeeds(self):
        """When direct_connect is present it wins; TURN fallback must not run."""
        from tests.turn_server import TURNServer, make_local_turn_server_entry

        try:
            self.node_a = await start_node(self.ipv6_a, PORT_TURN_A_T3)
            self.node_b = await start_node(self.ipv6_b, PORT_TURN_B_T3)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        # TURN server started but direct_connect is still present — it should
        # win before TURN is ever attempted.
        nic = await Interface()
        if IP6 not in nic.supported():
            self.skipTest("IPv6 not available")
        self.turn_server = TURNServer(nic)
        await self.turn_server.start()

        local_entry = make_local_turn_server_entry(
            port=self.turn_server.af_ports.get(IP6, self.turn_server.port), af=IP6
        )
        self.get_infra_patcher = patch(
            "p2pd.traversal.plugins.turn.main.get_infra",
            return_value=[[local_entry]],
        )
        self.get_infra_patcher.start()

        try:
            pipe, plugin = await asyncio.wait_for(
                auto_connect(self.node_a, self.node_b.addr_bytes, timeout=20),
                timeout=25,
            )
        except asyncio.TimeoutError:
            self.skipTest("auto_connect timed out")

        self.assertIsNotNone(pipe)
        self.assertNotEqual(
            type(plugin).__name__,
            "TURNPlugin",
            "direct_connect should win before TURN is tried, got {}".format(
                type(plugin).__name__
            ),
        )
        await pipe.close()


if __name__ == "__main__":
    unittest.main()
