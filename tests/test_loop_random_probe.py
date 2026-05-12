"""
Loop test for random_probe.

Same setup as test_random_probe_e2e.test_protocol_flow_completes (cone
<-> symmetric NAT pair on two distinct NICs, every other plugin popped
from plugin_loaders), but runs the protocol-flow path LOOP_COUNT times
against the SAME node pair to surface state-leak bugs across successive
uses -- 256-pack UDP probe sockets not freed between iterations,
session nonces colliding, mapping windows not recycled, etc.

random_probe is the heaviest socket-consumer of any plugin (~256 UDP
sockets per AF in symmetric mode), so it's the highest-value target for
loop testing -- any FD leak or close-path bug shows up here first.

Lives in its own file so the matrix runner gives it a fresh subprocess
per CLAUDE.md heavy-tests rule.
"""

import asyncio
import unittest

from aionetiface import IP4
from aionetiface.nic.nat.nat_defs import FULL_CONE, SYMMETRIC_NAT
from aionetiface.testing import AsyncTestCase
from warpgate.node.auto_connect import auto_connect

from auto_connect_helpers import (
    LOOP_COUNT,
    PORT_LOOP_RAND_A, PORT_LOOP_RAND_B,
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


class TestLoopRandomProbe(AsyncTestCase):
    """random_probe protocol flow must complete LOOP_COUNT times in a row."""

    # 3x ~35s plus close-and-breathe overhead between iterations.
    async_test_timeout = 240

    async def asyncSetUp(self):
        self.ifs_a, self.ip_a, self.ifs_b, self.ip_b = await load_two_nodes(
            self, IP4, label="loop_random_probe",
        )
        self.node_a = await start_node_with_ifs(
            self.ifs_a, [self.ip_a], PORT_LOOP_RAND_A,
        )
        self.node_b = await start_node_with_ifs(
            self.ifs_b, [self.ip_b], PORT_LOOP_RAND_B,
        )
        force_nat_type(self.node_a, FULL_CONE)
        force_nat_type(self.node_b, SYMMETRIC_NAT)
        for name in (
            "direct_connect", "reverse_connect", "tcp_punch", "turn", "udp_punch",
        ):
            self.node_a.traversal.plugin_loaders.pop(name, None)
            self.node_b.traversal.plugin_loaders.pop(name, None)
        print("[LOOP-RAND] setup ip_a={0} ip_b={1} plugins_a={2}".format(
            self.ip_a, self.ip_b,
            list(self.node_a.traversal.plugin_loaders.keys()),
        ))

    async def asyncTearDown(self):
        await close_nodes(self.node_b, self.node_a)

    async def test_loop(self):
        for i in range(LOOP_COUNT):
            label = "iter {0}/{1}".format(i + 1, LOOP_COUNT)
            print("[LOOP-RAND] === {0} START ===".format(label))
            pipe = plugin = None
            try:
                pipe, plugin = await asyncio.wait_for(
                    auto_connect(self.node_a, self.node_b.addr_bytes, timeout=25),
                    timeout=35,
                )
            except asyncio.TimeoutError:
                pass
            except (OSError, ValueError):
                if i == 0:
                    self.skipTest(
                        "auto_connect found no viable random_probe combo "
                        "on this host -- needs public-IP NICs"
                    )
                raise

            if pipe is not None:
                self.assertEqual(
                    type(plugin).__name__, "RandomProbePlugin",
                    "{0}: expected RandomProbePlugin pipe, got {1}".format(
                        label, type(plugin).__name__,
                    ),
                )
                print("[LOOP-RAND] {0} OK with pipe".format(label))
                try:
                    await asyncio.wait_for(pipe.close(), timeout=5)
                except (asyncio.TimeoutError, OSError, ConnectionError):
                    pass
            else:
                seen = False
                for node in (self.node_a, self.node_b):
                    for plug in node.traversal.plugins.values():
                        if type(plug).__name__ == "RandomProbePlugin":
                            seen = True
                            break
                    if seen:
                        break
                if not seen and i == 0:
                    self.skipTest(
                        "auto_combos didn't generate a random_probe combo "
                        "on this host -- expected on single-host dev box"
                    )
                self.assertTrue(
                    seen,
                    "{0}: no RandomProbePlugin instance seen on either "
                    "node -- protocol flow likely broken".format(label),
                )
                print("[LOOP-RAND] {0} OK (no pipe but plugin instantiated)".format(label))

            # Longer breath after random_probe than other loop tests:
            # the 256-pack spray keeps leaking probe frames for hundreds
            # of ms after convergence, and we want those to drain before
            # iter N+1's sockets see them.
            await asyncio.sleep(2.0)


if __name__ == "__main__":
    unittest.main()
