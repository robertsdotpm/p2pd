"""
Tests for link-local IPv6 support with the --ip flag in p2pd Node.

Covers three scenarios:
  1. sort_ips_by_nic finds a link-local on a NIC that has NO global IPv6 routes
     (the link-local lives only in RoutePool.link_locals, not on any route).
  2. Node.__init__ with ip=["fe80::1"] raises no "IP not found" exception.
  3. make_node_addr correctly encodes the link-local as the NIC IPv6 field in the
     node address, and parse_node_addr can read it back.


"""

import socket
import asyncio
import unittest
from aionetiface import IP4, IP6
from aionetiface.net.ip_range import IPRange as IPR
from aionetiface.net.net_defs import DUEL_STACK
from aionetiface.nic.nat.nat_utils import nat_info, delta_info
from aionetiface.nic.nat.nat_defs import OPEN_INTERNET, NA_DELTA
from aionetiface.nic.route.route import Route
from aionetiface.nic.route.route_pool import RoutePool
from aionetiface.nic.route.rp_from_ip import sort_ips_by_nic, route_pool_from_ips
from aionetiface.nic.interface import Interface
from aionetiface.net.topology import make_node_addr, parse_node_addr

from p2pd.node.node import Node
from p2pd.node.node_defs import NODE_TEST_CONF

# Canonical (fully-expanded) forms used throughout.
LINK_LOCAL = str(IPR("fe80::1"))  # fe80:0000:0000:0000:0000:0000:0000:0001
GLOBAL_V6 = str(IPR("2606:4700:4700::1111"))  # Cloudflare DNS - truly public
LAN_V4 = "192.168.1.10"
WAN_V4 = "8.8.8.8"
PORT = 10001
PUB_KEY = "93e9d6f7e7791ea06544557a2"
MACHINE_ID = "c88e78bafc408223a97b560ea94f1bb4d5fc58a5705a41a2a94d54466d552816"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _base_nat():
    return nat_info(OPEN_INTERNET, delta_info(NA_DELTA, 0))


def _build_interface(rp_v4, rp_v6):
    """
    Construct an Interface-like object bypassing network I/O.
    Sets every attribute that make_node_addr / sort_ips_by_nic need.
    """
    nic = Interface.__new__(Interface)
    nic.__name__ = "Interface"
    nic.id = "mock0"
    nic.name = "eth0"
    nic.nic_no = 0
    nic.resolved = True
    nic.netiface_index = 0
    nic.nat = _base_nat()
    nic.mac = ""
    nic.v4_lan_ips = []
    nic.guid = None
    nic.stack = DUEL_STACK
    nic.netifaces = None
    nic.timeout = 4
    nic.rp = {IP4: rp_v4, IP6: rp_v6}
    return nic


def _v4_route_pool():
    """A minimal IPv4 route pool for a NIC behind a simple NAT."""
    nic_ipr = IPR(LAN_V4)
    ext_ipr = IPR(WAN_V4)
    route = Route(IP4, [nic_ipr], [ext_ipr], None)
    return RoutePool([route])


def _v4_local_only_route_pool():
    """IPv4 route pool with no global route — only a private LAN IP.
    Simulates a NIC where STUN failed (no internet access).
    The private IP is stored in RoutePool.link_locals as a local fallback."""
    priv_ipr = IPR(LAN_V4)
    return RoutePool(routes=[], link_locals=[priv_ipr])


def _nic_link_local_only():
    """
    NIC with link-local IPv6 only — no global IPv6 routes.
    The link-local is stored in RoutePool.link_locals but there are no Route
    objects for IPv6, which is the bug trigger.
    """
    ll = IPR(LINK_LOCAL)
    rp_v6 = RoutePool(routes=[], link_locals=[ll])
    return _build_interface(_v4_route_pool(), rp_v6)


def _nic_global_v6_with_link_local():
    """
    NIC with both a global IPv6 route and a link-local.
    The link-local is set on the route AND in RoutePool.link_locals.
    """
    ll = IPR(LINK_LOCAL)
    v6ext = IPR(GLOBAL_V6)
    route = Route(IP6, [v6ext], [v6ext], None)
    route.set_link_locals([ll])
    rp_v6 = RoutePool([route], link_locals=[ll])
    return _build_interface(_v4_route_pool(), rp_v6)


# ---------------------------------------------------------------------------
# 1. sort_ips_by_nic with link-local
# ---------------------------------------------------------------------------
class TestSortIpsByNicLinkLocal(unittest.TestCase):
    """sort_ips_by_nic must locate a link-local regardless of whether the NIC
    has global IPv6 routes."""

    def test_finds_link_local_when_no_global_v6_routes(self):
        """Bug: link-local is only in RoutePool.link_locals, not on any Route.
        sort_ips_by_nic must still find it."""
        nic = _nic_link_local_only()
        result = sort_ips_by_nic([LINK_LOCAL], [nic])
        self.assertIn(
            LINK_LOCAL,
            result["mock0"],
            "link-local not found on NIC that only has "
            "RoutePool-level link_locals (no global IPv6 routes)",
        )

    def test_finds_link_local_via_route_link_locals(self):
        """When the NIC has a global IPv6 route with link_locals set,
        the link-local is found through the route iteration path."""
        nic = _nic_global_v6_with_link_local()
        result = sort_ips_by_nic([LINK_LOCAL], [nic])
        self.assertIn(
            LINK_LOCAL, result["mock0"], "link-local not found via route.link_locals"
        )

    def test_non_link_local_ip_not_confused_with_link_local(self):
        """Passing a WAN IPv4 should not accidentally match the link-local."""
        nic = _nic_link_local_only()
        result = sort_ips_by_nic([WAN_V4], [nic])
        self.assertNotIn(LINK_LOCAL, result["mock0"])


# ---------------------------------------------------------------------------
# 2. Node.__init__ with --ip as link-local
# ---------------------------------------------------------------------------
class TestNodeInitLinkLocalIP(unittest.TestCase):
    """Node(ip=["<link-local>"]) must not raise an exception about the IP
    being unfindable on any interface."""

    def setUp(self):
        self._rw = socket.socketpair()
        self._rw[0].setblocking(False)
        self._rw[1].setblocking(True)

    def tearDown(self):
        for s in self._rw:
            try:
                s.close()
            except Exception:
                pass

    def test_link_local_only_nic_does_not_raise(self):
        """Regression: --ip fe80::1 on a NIC with no global IPv6 used to raise
        'listen IPs not found on any interface'."""
        nic = _nic_link_local_only()
        # Should not raise.
        node = Node(
            ifs=[nic],
            ip=["fe80::1"],
            port=PORT,
            stop_rw=self._rw,
            conf=NODE_TEST_CONF,
        )
        # The normalised form of fe80::1 must be in listen_ips.
        self.assertIn(LINK_LOCAL, node.listen_ips)

    def test_link_local_with_global_v6_does_not_raise(self):
        """Same test for a NIC that has both global IPv6 and link-local."""
        nic = _nic_global_v6_with_link_local()
        node = Node(
            ifs=[nic],
            ip=["fe80::1"],
            port=PORT,
            stop_rw=self._rw,
            conf=NODE_TEST_CONF,
        )
        self.assertIn(LINK_LOCAL, node.listen_ips)


# ---------------------------------------------------------------------------
# 3. make_node_addr encodes link-local as the IPv6 NIC field
# ---------------------------------------------------------------------------
class TestMakeNodeAddrLinkLocal(unittest.TestCase):
    """When the route has link_locals set, make_node_addr must use the
    link-local as the 'nic' (internal) IPv6 in the encoded address."""

    def _addr_for(self, nic):
        return make_node_addr(PUB_KEY, MACHINE_ID, [nic], port=PORT)

    def test_link_local_encoded_as_nic_ip_in_addr(self):
        nic = _nic_global_v6_with_link_local()
        addr = self._addr_for(nic)
        parsed = parse_node_addr(addr)

        self.assertGreater(len(parsed[IP6]), 0, "Expected IPv6 entries in node address")
        nic_ip = parsed[IP6][0]["nic"]
        self.assertEqual(
            str(nic_ip),
            LINK_LOCAL,
            "NIC IPv6 in address should be the link-local {}, got {}".format(repr(LINK_LOCAL), repr(str(nic_ip))),
        )

    def test_global_v6_encoded_as_ext_ip_in_addr(self):
        """The external IPv6 must remain the global address, not the link-local."""
        nic = _nic_global_v6_with_link_local()
        addr = self._addr_for(nic)
        parsed = parse_node_addr(addr)

        ext_ip = parsed[IP6][0]["ext"]
        self.assertEqual(
            str(ext_ip),
            GLOBAL_V6,
            "EXT IPv6 in address should be the global {}, got {}".format(repr(GLOBAL_V6), repr(str(ext_ip))),
        )

    def test_addr_roundtrip_with_link_local(self):
        """parse_node_addr(make_node_addr(...)) must succeed and preserve all fields."""
        nic = _nic_global_v6_with_link_local()
        addr = self._addr_for(nic)
        parsed = parse_node_addr(addr)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["pub_key_hex"], PUB_KEY)
        self.assertEqual(parsed["machine_id"], MACHINE_ID)
        self.assertGreater(len(parsed[IP4]), 0)
        self.assertGreater(len(parsed[IP6]), 0)

    def test_link_local_only_nic_builds_v6_addr_entry(self):
        """A link-local-only NIC (no global IPv6) must still produce an IPv6
        entry in the address so the link-local is reachable on the local link."""
        nic = _nic_link_local_only()
        addr = self._addr_for(nic)
        parsed = parse_node_addr(addr)

        self.assertIsNotNone(parsed, "parse_node_addr returned None")
        self.assertGreater(
            len(parsed[IP6]),
            0,
            "Expected IPv6 entry for link-local-only NIC in node address",
        )
        nic_ip = parsed[IP6][0]["nic"]
        self.assertEqual(
            str(nic_ip), LINK_LOCAL, "NIC IPv6 field should contain the link-local"
        )


# ---------------------------------------------------------------------------
# 4. IPv4 local-only fallback (no global WAN resolved)
# ---------------------------------------------------------------------------
class TestMakeNodeAddrLocalIPv4Fallback(unittest.TestCase):
    """When a NIC has a private IPv4 but no global route was resolved (e.g.
    STUN failed because there is no internet access), make_node_addr must
    still include the private IP so LAN peers can reach the node."""

    def _nic_local_v4_only(self):
        """NIC where IPv4 STUN failed — private IP stored in link_locals."""
        return _build_interface(
            _v4_local_only_route_pool(),
            RoutePool(),  # no IPv6
        )

    def _addr_for(self, nic):
        return make_node_addr(PUB_KEY, MACHINE_ID, [nic], port=PORT)

    def test_local_ipv4_encoded_when_no_global_route(self):
        """Regression: private IPv4 must appear in the address even when
        no WAN route was resolved (link_locals fallback path)."""
        nic = self._nic_local_v4_only()
        addr = self._addr_for(nic)
        parsed = parse_node_addr(addr)

        self.assertIsNotNone(parsed)
        self.assertGreater(
            len(parsed[IP4]),
            0,
            "Expected IPv4 entry for local-only NIC in node address",
        )
        ext_ip = parsed[IP4][0]["ext"]
        nic_ip = parsed[IP4][0]["nic"]
        self.assertEqual(
            str(ext_ip),
            LAN_V4,
            "ext IPv4 should be the LAN IP {}, got {}".format(repr(LAN_V4), repr(str(ext_ip))),
        )
        self.assertEqual(
            str(nic_ip),
            LAN_V4,
            "nic IPv4 should be the LAN IP {}, got {}".format(repr(LAN_V4), repr(str(nic_ip))),
        )

    def test_sort_ips_by_nic_finds_local_ipv4(self):
        """sort_ips_by_nic must locate a private IPv4 stored in link_locals
        (same fix as for IPv6 link-locals)."""
        nic = self._nic_local_v4_only()
        result = sort_ips_by_nic([LAN_V4], [nic])
        self.assertIn(
            LAN_V4,
            result["mock0"],
            "private IPv4 not found on NIC with no global route",
        )

    def test_global_route_takes_precedence_over_link_locals(self):
        """When a global IPv4 route exists the link_locals fallback must not
        interfere — the global route should be used as normal."""
        nic = _build_interface(_v4_route_pool(), RoutePool())
        addr = self._addr_for(nic)
        parsed = parse_node_addr(addr)

        ext_ip = parsed[IP4][0]["ext"]
        self.assertEqual(
            str(ext_ip), WAN_V4, "global WAN IP should be used when a route exists"
        )


if __name__ == "__main__":
    unittest.main()
