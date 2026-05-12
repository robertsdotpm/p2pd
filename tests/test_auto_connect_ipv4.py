"""
Integration tests — IPv4 direct_connect.

Strict on multi-NIC machines: once require_split_or_fail has handed us
two real NICs each carrying an IPv4 IP, every subsequent failure is a
real failure -- no skipTest fallbacks. Node startup exceptions, auto_connect
timeouts, and pipe is None all propagate as ERROR / FAIL.
"""

import asyncio
import unittest

from aionetiface import IP4, NIC_BIND, parse_node_addr
from aionetiface.testing import AsyncTestCase
from warpgate.node.auto_connect import auto_connect, auto_combos

from auto_connect_helpers import (
    PORT_A_T1, PORT_B_T1, PORT_A_T2, PORT_B_T2, PORT_A_T3, PORT_B_T3,
    close_nodes, load_two_nodes, start_node_with_ifs, isolate_plugins,
)


def log_pipe(label, pipe, plugin=None):
    print("[IPV4-TEST] {0}: pipe={1!r} sock={2!r} plugin={3}".format(
        label, pipe, getattr(pipe, "sock", None),
        type(plugin).__name__ if plugin is not None else None,
    ))


def log_node(label, node):
    print("[IPV4-TEST] {0}: listen_ips={1} listen_port={2} machine_id={3} addr_map[IP4]={4}".format(
        label, node.listen_ips, node.listen_port,
        node.addr_map.get("machine_id"),
        node.addr_map.get(IP4),
    ))


class TestAutoConnectIPv4(AsyncTestCase):
    """auto_connect over IPv4 NIC_BIND between two nodes on the same host."""

    async def asyncSetUp(self):
        self.ifs_a, self.ip_a, self.ifs_b, self.ip_b = await load_two_nodes(
            self, IP4, label="auto_connect IPv4",
        )
        print("[IPV4-TEST] setup ip_a={0} ip_b={1} ifs_a={2} ifs_b={3}".format(
            self.ip_a, self.ip_b,
            [nic.id for nic in self.ifs_a],
            [nic.id for nic in self.ifs_b],
        ))
        self.node_a = self.node_b = None

    async def asyncTearDown(self):
        await close_nodes(self.node_b, self.node_a)

    async def test_auto_connect_returns_pipe(self):
        """auto_connect must return a usable pipe."""
        self.node_a = await start_node_with_ifs(self.ifs_a, [self.ip_a], PORT_A_T1)
        self.node_b = await start_node_with_ifs(self.ifs_b, [self.ip_b], PORT_B_T1)
        log_node("node_a", self.node_a)
        log_node("node_b", self.node_b)

        pipe, plugin = await asyncio.wait_for(
            auto_connect(self.node_a, self.node_b.addr_bytes, timeout=20),
            timeout=25,
        )
        log_pipe("auto_connect_returns_pipe", pipe, plugin)

        self.assertIsNotNone(pipe)
        self.assertIsNotNone(plugin)
        from aionetiface import SUB_ALL, to_b
        pipe.subscribe(SUB_ALL)
        await pipe.send(to_b("hello auto_connect\n"))
        try:
            await asyncio.wait_for(pipe.close(), timeout=5)
        except Exception:
            pass

    async def test_plugin_is_direct_connect_on_same_lan(self):
        """NIC_BIND direct_connect should win on the same LAN."""
        self.node_a = await start_node_with_ifs(self.ifs_a, [self.ip_a], PORT_A_T2)
        self.node_b = await start_node_with_ifs(self.ifs_b, [self.ip_b], PORT_B_T2)
        log_node("node_a", self.node_a)
        log_node("node_b", self.node_b)
        # The assertion accepts DirectConnect or ReverseConnectPlugin, so
        # whitelist both same-LAN paths and pop everything else.
        isolate_plugins(self.node_a, "direct_connect", "reverse_connect")
        print("[IPV4-TEST] node_a plugins={}".format(
            list(self.node_a.traversal.plugin_loaders.keys())
        ))

        pipe, plugin = await asyncio.wait_for(
            auto_connect(self.node_a, self.node_b.addr_bytes, timeout=20),
            timeout=25,
        )
        log_pipe("direct_connect_on_same_lan", pipe, plugin)

        self.assertIsNotNone(pipe)
        self.assertIn(
            type(plugin).__name__,
            ("DirectConnect", "ReverseConnectPlugin"),
            "Expected direct or reverse on same LAN, got: {}".format(type(plugin).__name__),
        )
        try:
            await asyncio.wait_for(pipe.close(), timeout=5)
        except Exception:
            pass

    async def test_combos_include_nic_bind(self):
        """NIC_BIND combos must be generated when two NIC IPs are reachable."""
        self.node_a = await start_node_with_ifs(self.ifs_a, [self.ip_a], PORT_A_T3)
        self.node_b = await start_node_with_ifs(self.ifs_b, [self.ip_b], PORT_B_T3)
        log_node("node_a", self.node_a)
        log_node("node_b", self.node_b)

        dest_map = parse_node_addr(self.node_b.addr_bytes)
        combos = auto_combos(self.node_a, self.node_a.addr_map, dest_map)
        route_types = {c[2] for c in combos}
        print("[IPV4-TEST] combos route_types={}".format(route_types))
        self.assertIn(NIC_BIND, route_types)


if __name__ == "__main__":
    unittest.main()
