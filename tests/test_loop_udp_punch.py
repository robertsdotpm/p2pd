"""
Loop test for udp_punch.

Same setup as test_udp_punch_e2e (cone <-> restricted-port NAT pair on
two distinct NICs, every other plugin popped from plugin_loaders),
but runs the protocol-flow path LOOP_COUNT times against the SAME
node pair to surface state-leak bugs across successive uses --
prediction sockets not freed between runs, mapping windows not
recycled, plugin slots not closed, etc.

Inherits the same accept-criterion as the single-shot test (a pipe
OR a plugin instance OR a clean skip), since udp_punch on a single-
host dev box won't always produce a real pipe -- the test value is
"the cleanup path runs to completion without crashing on iter 2/3".

Lives in its own file so the matrix runner gives it a fresh subprocess
per CLAUDE.md heavy-tests rule.
"""

import asyncio
import unittest

from aionetiface import IP4
from aionetiface.nic.nat.nat_defs import FULL_CONE, RESTRICT_PORT_NAT
from aionetiface.testing import AsyncTestCase
from warpgate.node.auto_connect import auto_connect

from auto_connect_helpers import (
    LOOP_COUNT,
    PORT_LOOP_UDP_PUNCH_A, PORT_LOOP_UDP_PUNCH_B,
    PUNCH_TEST_CONF,
    close_nodes, load_two_nodes, start_node_with_ifs,
)


def force_nat_type(node, nat_type):
    addr_map = node.addr_map or {}
    for af in (IP4,):
        ifs = addr_map.get(af) or {}
        for if_info in ifs.values():
            nat = if_info.get("nat")
            if nat is None:
                if_info["nat"] = {
                    "type": nat_type, "delta": {"type": 0, "value": 0},
                }
            else:
                nat["type"] = nat_type


class TestLoopUdpPunch(AsyncTestCase):
    """udp_punch protocol flow must complete LOOP_COUNT times in a row."""

    # 3x ~30s plus close-and-breathe overhead.
    async_test_timeout = 240

    async def asyncSetUp(self):
        self.ifs_a, self.ip_a, self.ifs_b, self.ip_b = await load_two_nodes(
            self, IP4, label="loop_udp_punch",
        )
        self.node_a = await start_node_with_ifs(
            self.ifs_a, [self.ip_a], PORT_LOOP_UDP_PUNCH_A, conf=PUNCH_TEST_CONF,
        )
        self.node_b = await start_node_with_ifs(
            self.ifs_b, [self.ip_b], PORT_LOOP_UDP_PUNCH_B, conf=PUNCH_TEST_CONF,
        )
        force_nat_type(self.node_a, FULL_CONE)
        force_nat_type(self.node_b, RESTRICT_PORT_NAT)
        for name in (
            "direct_connect", "reverse_connect", "tcp_punch",
            "turn", "random_probe",
        ):
            self.node_a.traversal.plugin_loaders.pop(name, None)
            self.node_b.traversal.plugin_loaders.pop(name, None)
        print("[LOOP-UDP-PUNCH] setup ip_a={0} ip_b={1} plugins_a={2}".format(
            self.ip_a, self.ip_b,
            list(self.node_a.traversal.plugin_loaders.keys()),
        ))

    async def asyncTearDown(self):
        await close_nodes(self.node_b, self.node_a)

    async def test_loop(self):
        for i in range(LOOP_COUNT):
            label = "iter {0}/{1}".format(i + 1, LOOP_COUNT)
            print("[LOOP-UDP-PUNCH] === {0} START ===".format(label))
            pipe = plugin = None
            try:
                pipe, plugin = await asyncio.wait_for(
                    auto_connect(self.node_a, self.node_b.addr_bytes, timeout=20),
                    timeout=30,
                )
            except asyncio.TimeoutError:
                pass
            except (OSError, ValueError):
                # First iteration didn't find a viable combo -- the
                # platform can't drive this test at all, no point in
                # looping.
                if i == 0:
                    self.skipTest(
                        "auto_connect found no viable udp_punch combo "
                        "on this host (cone, restricted-port) -- needs "
                        "real public-IP NICs"
                    )
                raise

            if pipe is not None:
                self.assertEqual(
                    type(plugin).__name__, "UdpPunchPlugin",
                    "{0}: expected UdpPunchPlugin pipe, got {1}".format(
                        label, type(plugin).__name__,
                    ),
                )
                print("[LOOP-UDP-PUNCH] {0} OK with pipe".format(label))
                try:
                    await asyncio.wait_for(pipe.close(), timeout=5)
                except (asyncio.TimeoutError, OSError, ConnectionError):
                    pass
            else:
                # No pipe -- confirm at least one side instantiated the
                # plugin (matches the single-shot test's accept criterion).
                seen = False
                for node in (self.node_a, self.node_b):
                    for plug in node.traversal.plugins.values():
                        if type(plug).__name__ == "UdpPunchPlugin":
                            seen = True
                            break
                    if seen:
                        break
                if not seen and i == 0:
                    self.skipTest(
                        "auto_combos didn't generate a udp_punch combo "
                        "on this host -- expected on single-host dev box"
                    )
                self.assertTrue(
                    seen,
                    "{0}: no UdpPunchPlugin instance seen on either "
                    "node -- protocol flow likely broken".format(label),
                )
                print("[LOOP-UDP-PUNCH] {0} OK (no pipe but plugin instantiated)".format(label))

            await asyncio.sleep(1.0)


if __name__ == "__main__":
    unittest.main()
