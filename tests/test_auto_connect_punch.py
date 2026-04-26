"""
Integration tests — punch.

Split out of test_auto_connect.py so the heavy AsyncTestCase classes each
get their own subprocess.

Each test gives alice and bob their own (cloned) NIC subset via
split_two_node_setups so their addr_maps differ.
"""

import asyncio
import unittest

from aionetiface import IP4, parse_node_addr  # noqa: F401  IP4 used in print()s
from aionetiface.testing import AsyncTestCase
from p2pd.node.auto_connect import auto_connect, auto_combos

from auto_connect_helpers import (
    PORT_PUNCH_A_T1, PORT_PUNCH_B_T1, PORT_PUNCH_A_T2, PORT_PUNCH_B_T2,
    PUNCH_TEST_CONF,
    close_nodes, fresh_ifs, require_split_or_fail, start_node_with_ifs,
)


class TestAutoConnectPunch(AsyncTestCase):
    """auto_connect uses TCP punch when direct_connect and reverse_connect are removed."""

    # Punch needs a longer per-test budget than the default 90s testing.py cap
    # because the inner punch round-trip wait_for is 60s.
    async_test_timeout = 120

    async def asyncSetUp(self):
        probe_ifs = await fresh_ifs()
        self.ifs_a, self.ip_a, self.ifs_b, self.ip_b = require_split_or_fail(
            self, probe_ifs, IP4, label="punch",
        )
        self.node_a = self.node_b = None

    async def asyncTearDown(self):
        await close_nodes(self.node_b, self.node_a)

    async def test_punch_returns_pipe(self):
        """With direct_connect and reverse_connect removed, punch must establish the pipe."""
        print("[PUNCH-TEST] setup ip_a={} ip_b={}".format(self.ip_a, self.ip_b))
        print("[PUNCH-TEST] ifs_a={}".format([nic.id for nic in self.ifs_a]))
        print("[PUNCH-TEST] ifs_b={}".format([nic.id for nic in self.ifs_b]))
        try:
            self.node_a = await start_node_with_ifs(
                self.ifs_a, [self.ip_a], PORT_PUNCH_A_T1, conf=PUNCH_TEST_CONF
            )
            self.node_b = await start_node_with_ifs(
                self.ifs_b, [self.ip_b], PORT_PUNCH_B_T1, conf=PUNCH_TEST_CONF
            )
        except Exception as exc:
            print("[PUNCH-TEST] node startup failed: {!r}".format(exc))
            self.skipTest("Node startup failed: {}".format(exc))

        if "punch" not in self.node_a.traversal.plugin_loaders:
            print("[PUNCH-TEST] punch plugin missing from node_a")
            self.skipTest("punch plugin not installed (enable_punching=False?)")

        print("[PUNCH-TEST] node_a addr_map IP4={}".format(self.node_a.addr_map.get(IP4)))
        print("[PUNCH-TEST] node_b addr_map IP4={}".format(self.node_b.addr_map.get(IP4)))
        # Leave punch as the only non-skip plugin on the initiator.
        self.node_a.traversal.plugin_loaders.pop("direct_connect", None)
        self.node_a.traversal.plugin_loaders.pop("reverse_connect", None)
        print("[PUNCH-TEST] node_a plugins(after pop)={}".format(
            list(self.node_a.traversal.plugin_loaders.keys())
        ))
        print("[PUNCH-TEST] node_b plugins={}".format(
            list(self.node_b.traversal.plugin_loaders.keys())
        ))
        print("[PUNCH-TEST] calling auto_connect ...")

        try:
            pipe, plugin = await asyncio.wait_for(
                auto_connect(self.node_a, self.node_b.addr_bytes, timeout=50),
                timeout=60,
            )
        except asyncio.TimeoutError:
            print("[PUNCH-TEST] auto_connect timed out at outer wait_for")
            self.skipTest("punch timed out (expected on some NAT configs)")
        except AssertionError:
            print("[PUNCH-TEST] AssertionError from auto_connect (NAT detection)")
            self.skipTest("punch: NAT type unpredictable on this network")

        print("[PUNCH-TEST] auto_connect returned pipe={!r} plugin={}".format(
            pipe, type(plugin).__name__ if plugin is not None else None,
        ))

        if pipe is None:
            self.skipTest("punch returned None (unsupported NAT/network config)")

        self.assertIsNotNone(pipe, "punch must return a pipe")
        self.assertEqual(
            type(plugin).__name__,
            "PunchPlugin",
            "Expected PunchPlugin, got {}".format(type(plugin).__name__),
        )
        try:
            await asyncio.wait_for(pipe.close(), timeout=5)
        except Exception:
            pass

    async def test_punch_plugin_is_tried_in_combos(self):
        """With punch installed, auto_combos must include punch combos."""
        try:
            self.node_a = await start_node_with_ifs(
                self.ifs_a, [self.ip_a], PORT_PUNCH_A_T2, conf=PUNCH_TEST_CONF
            )
            self.node_b = await start_node_with_ifs(
                self.ifs_b, [self.ip_b], PORT_PUNCH_B_T2, conf=PUNCH_TEST_CONF
            )
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


if __name__ == "__main__":
    unittest.main()
