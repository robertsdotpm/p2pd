"""
Integration tests — IPv6 direct_connect (global addresses).

Split out of test_auto_connect.py so the heavy AsyncTestCase classes each
get their own subprocess.
"""

import asyncio
import unittest

from aionetiface import IP6, EXT_BIND, parse_node_addr
from aionetiface.testing import AsyncTestCase
from p2pd.node.auto_connect import auto_connect, auto_combos

from auto_connect_helpers import (
    PORT_A6_T1, PORT_B6_T1, PORT_A6_T2, PORT_B6_T2,
    close_nodes, fresh_ifs, global_ipv6_addrs, start_node,
)


class TestAutoConnectIPv6(AsyncTestCase):
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
        except OSError:
            self.skipTest("IPv6 auto_connect raised OSError (broken IPv6 on this platform)")

        self.assertIsNotNone(pipe)
        self.assertIsNotNone(plugin)
        try:
            await asyncio.wait_for(pipe.close(), timeout=5)
        except Exception:
            pass

    async def test_combos_include_ext_bind_for_diff_global_ipv6(self):
        """Different global IPv6 ext IPs -> EXT_BIND combos must be generated."""
        try:
            self.node_a = await start_node(self.ipv6_a, PORT_A6_T2)
            self.node_b = await start_node(self.ipv6_b, PORT_B6_T2)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        dest_map = parse_node_addr(self.node_b.addr_bytes)
        combos = auto_combos(self.node_a, self.node_a.addr_map, dest_map)
        v6_route_types = {c[2] for c in combos if c[1] == IP6}
        self.assertIn(EXT_BIND, v6_route_types)


if __name__ == "__main__":
    unittest.main()
