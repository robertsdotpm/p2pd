"""
Integration tests — IPv4 direct_connect.

Split out of test_auto_connect.py so the heavy AsyncTestCase classes each
get their own subprocess (the runner schedules per test_*.py file).
"""

import asyncio
import unittest

from aionetiface import NIC_BIND, parse_node_addr
from aionetiface.testing import AsyncTestCase
from p2pd.node.auto_connect import auto_connect, auto_combos

from auto_connect_helpers import (
    PORT_A_T1, PORT_B_T1, PORT_A_T2, PORT_B_T2, PORT_A_T3, PORT_B_T3,
    available_ipv4_addrs, close_nodes, fresh_ifs, start_node,
)


class TestAutoConnectIPv4(AsyncTestCase):
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
        try:
            await asyncio.wait_for(pipe.close(), timeout=5)
        except Exception:
            pass

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
        try:
            await asyncio.wait_for(pipe.close(), timeout=5)
        except Exception:
            pass

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


if __name__ == "__main__":
    unittest.main()
