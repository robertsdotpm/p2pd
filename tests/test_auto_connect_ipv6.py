"""
Integration tests — IPv6 direct_connect.

Strict on multi-NIC machines: once require_split_or_fail has handed us
two real NICs each carrying an IPv6 IP, every subsequent failure is a
real failure -- no skipTest fallbacks.
"""

import asyncio
import unittest

from aionetiface import IP6, EXT_BIND, parse_node_addr
from aionetiface.testing import AsyncTestCase
from p2pd.node.auto_connect import auto_connect, auto_combos

from auto_connect_helpers import (
    PORT_A6_T1, PORT_B6_T1, PORT_A6_T2, PORT_B6_T2,
    close_nodes, load_two_nodes, start_node_with_ifs,
)


def log_pipe(label, pipe, plugin=None):
    print("[IPV6-TEST] {0}: pipe={1!r} sock={2!r} plugin={3}".format(
        label, pipe, getattr(pipe, "sock", None),
        type(plugin).__name__ if plugin is not None else None,
    ))


def log_node(label, node):
    print("[IPV6-TEST] {0}: listen_ips={1} listen_port={2} addr_map[IP6]={3}".format(
        label, node.listen_ips, node.listen_port, node.addr_map.get(IP6),
    ))


class TestAutoConnectIPv6(AsyncTestCase):
    """auto_connect over IPv6 EXT_BIND using two distinct global addresses."""

    async def asyncSetUp(self):
        self.ifs_a, self.ip_a, self.ifs_b, self.ip_b = await load_two_nodes(
            self, IP6, label="auto_connect IPv6",
        )
        print("[IPV6-TEST] setup ip_a={0} ip_b={1} ifs_a={2} ifs_b={3}".format(
            self.ip_a, self.ip_b,
            [nic.id for nic in self.ifs_a],
            [nic.id for nic in self.ifs_b],
        ))
        self.node_a = self.node_b = None

    async def asyncTearDown(self):
        await close_nodes(self.node_b, self.node_a)

    async def test_auto_connect_returns_pipe(self):
        """auto_connect on distinct global IPv6 addresses must return a pipe."""
        self.node_a = await start_node_with_ifs(self.ifs_a, [self.ip_a], PORT_A6_T1)
        self.node_b = await start_node_with_ifs(self.ifs_b, [self.ip_b], PORT_B6_T1)
        log_node("node_a", self.node_a)
        log_node("node_b", self.node_b)

        pipe, plugin = await asyncio.wait_for(
            auto_connect(self.node_a, self.node_b.addr_bytes, timeout=20),
            timeout=25,
        )
        log_pipe("auto_connect_returns_pipe", pipe, plugin)

        self.assertIsNotNone(pipe)
        self.assertIsNotNone(plugin)
        try:
            await asyncio.wait_for(pipe.close(), timeout=5)
        except Exception:
            pass

    async def test_combos_include_ext_bind_for_diff_global_ipv6(self):
        """Different global IPv6 ext IPs -> EXT_BIND combos must be generated."""
        self.node_a = await start_node_with_ifs(self.ifs_a, [self.ip_a], PORT_A6_T2)
        self.node_b = await start_node_with_ifs(self.ifs_b, [self.ip_b], PORT_B6_T2)
        log_node("node_a", self.node_a)
        log_node("node_b", self.node_b)

        dest_map = parse_node_addr(self.node_b.addr_bytes)
        combos = auto_combos(self.node_a, self.node_a.addr_map, dest_map)
        v6_route_types = {c[2] for c in combos if c[1] == IP6}
        print("[IPV6-TEST] v6 route_types={}".format(v6_route_types))
        self.assertIn(EXT_BIND, v6_route_types)


if __name__ == "__main__":
    unittest.main()
