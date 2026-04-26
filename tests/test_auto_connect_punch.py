"""
Integration tests — punch.

Strict on multi-NIC machines: once require_split_or_fail has handed us
two real NICs, every subsequent failure is a real failure -- no
skipTest fallbacks. Punch's NAT-detection assertions used to skipTest
on assertion errors; that masked real bugs and is gone now.
"""

import asyncio
import unittest

from aionetiface import IP4, SYMMETRIC_NAT, parse_node_addr  # noqa: F401  IP4 used in print()s
from aionetiface.testing import AsyncTestCase
from p2pd.node.auto_connect import auto_connect, auto_combos, is_same_machine

from auto_connect_helpers import (
    PORT_PUNCH_A_T1, PORT_PUNCH_B_T1, PORT_PUNCH_A_T2, PORT_PUNCH_B_T2,
    PUNCH_TEST_CONF,
    close_nodes, load_two_nodes, start_node_with_ifs,
)


def has_symmetric_nat(node) -> bool:
    """True iff any IP4 if_info on the node is classified as symmetric / hard NAT.

    The current punch algorithm cannot predict per-destination port
    mappings under symmetric NAT, so when either side has one the test
    can't expect punch to win. A separate symmetric-aware plugin is
    planned; until then, skip the assertion when this is the env.
    """
    for af in (IP4,):
        af_dict = node.addr_map.get(af) or {}
        for info in af_dict.values():
            nat = info.get("nat") or {}
            if nat.get("type") == SYMMETRIC_NAT:
                return True
            if nat.get("is_hard"):
                return True
    return False


def is_loopback_addr(s) -> bool:
    """Return True iff s parses as a 127.0.0.0/8 or ::1 loopback string."""
    if not s:
        return False
    s = str(s)
    if s.startswith("127."):
        return True
    if s == "::1" or s.startswith("::1"):
        return True
    return False


def all_punch_combos_loopback(node, dest_map) -> bool:
    """True iff every punch combo's dest IP is loopback.

    select_dest_ipr rewrites dest to the peer's loopback alias when
    same_pc=True, so on same-machine peers the only NIC_BIND combos
    that survive pair_distinct now point at 127.X.Y.Z. The current
    punch algorithm doesn't know how to traverse the loopback path
    (the rendezvous logic assumes a NAT in the middle), so the test
    can't usefully run here -- skip it. EXT_BIND combos are still
    counted; if any non-loopback path exists we let the test run.
    """
    found_any = False
    from p2pd.traversal.traversal_plugin import TraversalPlugin  # noqa: F401
    from p2pd.traversal.traversal_utils import select_dest_ipr
    from aionetiface import NIC_BIND, EXT_BIND
    src_map = node.addr_map
    same_pc = is_same_machine(src_map, dest_map)
    for combo in auto_combos(node, src_map, dest_map):
        plugin_name, af, route_type, src_info, dest_info = combo
        if plugin_name != "tcp_punch":
            continue
        found_any = True
        chosen = select_dest_ipr(af, same_pc, src_info, dest_info, [route_type])
        if chosen is None:
            continue
        if not is_loopback_addr(chosen):
            return False
    return found_any


class TestAutoConnectPunch(AsyncTestCase):
    """auto_connect uses TCP punch when direct_connect and reverse_connect are removed."""

    # Punch needs a longer per-test budget than the default 90s testing.py cap
    # because the inner punch round-trip wait_for is 60s.
    async_test_timeout = 120

    async def asyncSetUp(self):
        self.ifs_a, self.ip_a, self.ifs_b, self.ip_b = await load_two_nodes(
            self, IP4, label="tcp_punch",
        )
        print("[PUNCH-TEST] setup ip_a={0} ip_b={1} ifs_a={2} ifs_b={3}".format(
            self.ip_a, self.ip_b,
            [nic.id for nic in self.ifs_a],
            [nic.id for nic in self.ifs_b],
        ))
        self.node_a = self.node_b = None

    async def asyncTearDown(self):
        await close_nodes(self.node_b, self.node_a)

    async def test_punch_returns_pipe(self):
        """With direct_connect and reverse_connect removed, punch must establish the pipe."""
        self.node_a = await start_node_with_ifs(
            self.ifs_a, [self.ip_a], PORT_PUNCH_A_T1, conf=PUNCH_TEST_CONF
        )
        self.node_b = await start_node_with_ifs(
            self.ifs_b, [self.ip_b], PORT_PUNCH_B_T1, conf=PUNCH_TEST_CONF
        )
        print("[PUNCH-TEST] node_a addr_map IP4={0} listen_ips={1}".format(
            self.node_a.addr_map.get(IP4), self.node_a.listen_ips,
        ))
        print("[PUNCH-TEST] node_b addr_map IP4={0} listen_ips={1}".format(
            self.node_b.addr_map.get(IP4), self.node_b.listen_ips,
        ))

        # Skip when both peers are on the same machine. The only viable
        # NIC_BIND pair in that env is the loopback alias path, where
        # there is no NAT to traverse -- direct_connect already handles
        # the full job. Forcing punch through the predict_alloc /
        # rendezvous machinery here proves nothing about NAT traversal
        # and is silly in concept (no NAT exists).
        if is_same_machine(self.node_a.addr_map, self.node_b.addr_map):
            self.skipTest(
                "same-machine peers don't need NAT punching; "
                "direct_connect over loopback covers this topology"
            )

        # Skip when every punch combo would target a loopback address.
        # (Belt-and-braces against the same-machine case + any future
        # routing where select_dest_ipr ends up on 127.x for a punch
        # combo. The current punch algorithm doesn't drive the loopback
        # short-circuit, so a loopback-only combo set is a guaranteed
        # no-op.)
        dest_map_for_combos = parse_node_addr(self.node_b.addr_bytes)
        if all_punch_combos_loopback(self.node_a, dest_map_for_combos):
            self.skipTest(
                "every punch combo resolves to a loopback dest; "
                "punch path doesn't drive same-machine loopback"
            )

        # Skip when either side reports symmetric / hard NAT. The current
        # punch algorithm relies on predictable per-destination port
        # allocation; symmetric NAT defeats that. TURN ends up winning
        # in that env, which is the right behaviour but not what this
        # test asserts on.
        if has_symmetric_nat(self.node_a) or has_symmetric_nat(self.node_b):
            self.skipTest(
                "punch can't traverse symmetric NAT; "
                "node_a sym={0} node_b sym={1}".format(
                    has_symmetric_nat(self.node_a),
                    has_symmetric_nat(self.node_b),
                )
            )

        self.assertIn(
            "tcp_punch", self.node_a.traversal.plugin_loaders,
            "punch plugin not installed (enable_punching=False?)",
        )

        # Leave punch as the only non-skip plugin on the initiator.
        self.node_a.traversal.plugin_loaders.pop("direct_connect", None)
        self.node_a.traversal.plugin_loaders.pop("reverse_connect", None)
        print("[PUNCH-TEST] node_a plugins(after pop)={}".format(
            list(self.node_a.traversal.plugin_loaders.keys())
        ))

        pipe, plugin = await asyncio.wait_for(
            auto_connect(self.node_a, self.node_b.addr_bytes, timeout=50),
            timeout=60,
        )
        print("[PUNCH-TEST] pipe={0!r} sock={1!r} plugin={2}".format(
            pipe, getattr(pipe, "sock", None),
            type(plugin).__name__ if plugin is not None else None,
        ))

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
        self.node_a = await start_node_with_ifs(
            self.ifs_a, [self.ip_a], PORT_PUNCH_A_T2, conf=PUNCH_TEST_CONF
        )
        self.node_b = await start_node_with_ifs(
            self.ifs_b, [self.ip_b], PORT_PUNCH_B_T2, conf=PUNCH_TEST_CONF
        )
        self.assertIn(
            "tcp_punch", self.node_a.traversal.plugin_loaders,
            "punch plugin not installed",
        )

        dest_map = parse_node_addr(self.node_b.addr_bytes)
        combos = auto_combos(self.node_a, self.node_a.addr_map, dest_map)
        plugin_names = {c[0] for c in combos}
        print("[PUNCH-TEST] combos plugin_names={}".format(plugin_names))
        self.assertIn(
            "tcp_punch", plugin_names, "punch must appear in auto_connect combos"
        )


if __name__ == "__main__":
    unittest.main()
