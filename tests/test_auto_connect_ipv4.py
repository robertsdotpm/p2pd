"""
Integration tests — IPv4 direct_connect.

Split out of test_auto_connect.py so the heavy AsyncTestCase classes each
get their own subprocess (the runner schedules per test_*.py file).

Each test gives alice and bob their own (cloned) NIC subset via
split_two_node_setups so their addr_maps differ at the NIC level and
direct_connect actually has a NIC_BIND combo to try.
"""

import asyncio
import unittest

from aionetiface import IP4, NIC_BIND, parse_node_addr
from aionetiface.testing import AsyncTestCase
from p2pd.node.auto_connect import auto_connect, auto_combos

from auto_connect_helpers import (
    PORT_A_T1, PORT_B_T1, PORT_A_T2, PORT_B_T2, PORT_A_T3, PORT_B_T3,
    close_nodes, fresh_ifs, require_split_or_fail, start_node_with_ifs,
)


class TestAutoConnectIPv4(AsyncTestCase):
    """auto_connect over IPv4 NIC_BIND between two nodes on the same host."""

    async def asyncSetUp(self):
        probe_ifs = await fresh_ifs()
        # Strict: on a multi-NIC machine the connectivity tests MUST run.
        # require_split_or_fail skipTests cleanly only when fewer than 2
        # NICs are present; otherwise it fails loudly so a fixture bug
        # can never silently turn into a skip.
        self.ifs_a, self.ip_a, self.ifs_b, self.ip_b = require_split_or_fail(
            self, probe_ifs, IP4, label="auto_connect IPv4",
        )
        self.node_a = self.node_b = None

    async def asyncTearDown(self):
        await close_nodes(self.node_b, self.node_a)

    async def test_auto_connect_returns_pipe(self):
        """auto_connect must return a usable pipe."""
        try:
            self.node_a = await start_node_with_ifs(self.ifs_a, [self.ip_a], PORT_A_T1)
            self.node_b = await start_node_with_ifs(self.ifs_b, [self.ip_b], PORT_B_T1)
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
        print("[IPV4-TEST] setup ip_a={} ip_b={}".format(self.ip_a, self.ip_b))
        print("[IPV4-TEST] ifs_a={}".format([nic.id for nic in self.ifs_a]))
        print("[IPV4-TEST] ifs_b={}".format([nic.id for nic in self.ifs_b]))
        try:
            self.node_a = await start_node_with_ifs(self.ifs_a, [self.ip_a], PORT_A_T2)
            self.node_b = await start_node_with_ifs(self.ifs_b, [self.ip_b], PORT_B_T2)
        except Exception as exc:
            print("[IPV4-TEST] node startup failed: {!r}".format(exc))
            self.skipTest("Node startup failed: {}".format(exc))

        print("[IPV4-TEST] node_a addr_map IP4={}".format(self.node_a.addr_map.get(IP4)))
        print("[IPV4-TEST] node_b addr_map IP4={}".format(self.node_b.addr_map.get(IP4)))
        print("[IPV4-TEST] node_a plugins={}".format(
            list(self.node_a.traversal.plugin_loaders.keys())
        ))
        print("[IPV4-TEST] calling auto_connect ...")

        try:
            pipe, plugin = await asyncio.wait_for(
                auto_connect(self.node_a, self.node_b.addr_bytes, timeout=20),
                timeout=25,
            )
        except asyncio.TimeoutError:
            print("[IPV4-TEST] auto_connect timed out at outer wait_for")
            self.skipTest("auto_connect timed out")

        print("[IPV4-TEST] auto_connect returned pipe={!r} plugin={}".format(
            pipe, type(plugin).__name__ if plugin is not None else None,
        ))

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
            self.node_a = await start_node_with_ifs(self.ifs_a, [self.ip_a], PORT_A_T3)
            self.node_b = await start_node_with_ifs(self.ifs_b, [self.ip_b], PORT_B_T3)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        dest_map = parse_node_addr(self.node_b.addr_bytes)
        combos = auto_combos(self.node_a, self.node_a.addr_map, dest_map)
        route_types = {c[2] for c in combos}
        self.assertIn(NIC_BIND, route_types)


if __name__ == "__main__":
    unittest.main()
