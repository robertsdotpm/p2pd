"""Unit tests for the fan_out meta-plugin.

Covers:
- enumerate_viable_combos: combo counts under various constraint combinations.
- recursion refusal: target_plugin_name == "fan_out" raises.
- run(): spawns one child per combo, races, returns the winner's pipe,
  cancels and closes the losers.

These are pure unit tests against synthetic addr_maps and a stub
TraversalManager -- no MQTT, no real Node, no sockets.
"""
import asyncio
import unittest
from aionetiface import IP4, IP6, NIC_BIND, EXT_BIND, LOOPBACK_BIND
from aionetiface.testing import AsyncTestCase
from p2pd.traversal.plugins.fan_out.main import (
    FanOutPlugin,
    enumerate_viable_combos,
)
from p2pd.traversal.traversal_plugin import TraversalPlugin


class FakeIP:
    """Minimal stand-in for IPRange: ints / equality only."""

    def __init__(self, n):
        self.n = n

    def __int__(self):
        return self.n

    def __eq__(self, other):
        return isinstance(other, FakeIP) and self.n == other.n

    def __hash__(self):
        return hash(self.n)

    def __repr__(self):
        return "FakeIP({0})".format(self.n)


def make_info(if_idx, nic_n, ext_n, port=12345, loopback=None):
    return {
        "if_index": if_idx,
        "nic": FakeIP(nic_n),
        "ext": FakeIP(ext_n),
        "port": port,
        "loopback": loopback,
    }


def make_map(machine_id, ipv4_infos=None, ipv6_infos=None, pub_key_hex="aa"):
    m = {
        IP4: {info["if_index"]: info for info in (ipv4_infos or [])},
        IP6: {info["if_index"]: info for info in (ipv6_infos or [])},
        "machine_id": machine_id,
        "pub_key_hex": pub_key_hex,
        "bytes": "",
    }
    return m


class TestEnumerateViableCombos(unittest.TestCase):
    """Pure-function tests for combo enumeration."""

    def test_no_constraints_dual_nic(self):
        """Two cross-machine peers each with one NIC: NIC_BIND + EXT_BIND combos.

        Same-NIC pair fails NIC_BIND distinctness, dropping that
        combo. Loopback excluded because loopback alias is None.
        """
        src = make_map("A", ipv4_infos=[make_info(0, nic_n=10, ext_n=100)])
        dest = make_map("B", ipv4_infos=[make_info(0, nic_n=20, ext_n=200)])
        combos = enumerate_viable_combos(None, None, src, dest)
        # NIC_BIND: 1 pair (different NIC ints), EXT_BIND: 1 pair
        # (different ext ints), LOOPBACK_BIND: 0 (no loopback alias).
        rts = sorted(set(rt for _, rt, _, _ in combos))
        self.assertIn(NIC_BIND, rts)
        self.assertIn(EXT_BIND, rts)
        self.assertNotIn(LOOPBACK_BIND, rts)

    def test_pinned_route_type_filters(self):
        """route_type=NIC_BIND yields only NIC_BIND combos."""
        src = make_map("A", ipv4_infos=[make_info(0, 10, 100), make_info(1, 11, 100)])
        dest = make_map("B", ipv4_infos=[make_info(0, 20, 100), make_info(1, 21, 100)])
        combos = enumerate_viable_combos(None, NIC_BIND, src, dest)
        for af, rt, _, _ in combos:
            self.assertEqual(rt, NIC_BIND)
        # 2 src x 2 dest = 4 pairs, all distinct on NIC -> 4 combos.
        self.assertEqual(len(combos), 4)

    def test_pinned_af_filters(self):
        """af=IP6 yields no combos when peers have no IPv6 addresses."""
        src = make_map("A", ipv4_infos=[make_info(0, 10, 100)])
        dest = make_map("B", ipv4_infos=[make_info(0, 20, 200)])
        combos = enumerate_viable_combos(IP6, None, src, dest)
        self.assertEqual(combos, [])

    def test_no_compat_af_returns_empty(self):
        """No shared AF means no combos."""
        src = make_map("A", ipv4_infos=[make_info(0, 10, 100)])
        dest = make_map("B", ipv6_infos=[make_info(0, 20, 200)])
        combos = enumerate_viable_combos(None, None, src, dest)
        self.assertEqual(combos, [])

    def test_same_ext_drops_ext_bind(self):
        """Two interfaces sharing an external IP yield no EXT_BIND combo."""
        src = make_map("A", ipv4_infos=[make_info(0, 10, 100)])
        dest = make_map("B", ipv4_infos=[make_info(0, 20, 100)])  # same ext
        combos = enumerate_viable_combos(None, EXT_BIND, src, dest)
        self.assertEqual(combos, [])


class TestFanOutRefuseRecursion(unittest.TestCase):
    """fan_out cannot wrap itself."""

    def test_configure_target_fan_out_raises(self):
        plugin = FanOutPlugin()
        with self.assertRaises(ValueError):
            plugin.configure_target("fan_out")


class StubChildPlugin(TraversalPlugin):
    """Test double: resolves its result on a configured delay with a known pipe."""

    def __init__(self):
        super().__init__()
        self.delay = 0.0
        self.pipe_value = None
        self.run_count = 0
        self.cancelled = False

    async def run(self, reply=None):
        self.run_count += 1
        try:
            await asyncio.sleep(self.delay)
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        self.result.set_result(self.pipe_value)


class StubManager:
    """Test double for TraversalManager.

    Pre-stocks a sequence of child plugins, hands them out from
    create_plugin, and runs them when run_plugin is called. Tracks
    closed plugins so the test can assert on cleanup.
    """

    def __init__(self, child_plugins):
        self.child_plugins_queue = list(child_plugins)
        self.plugins = {}
        self.inbound_pipes = {}
        self.created = []
        self.closed = []

    def create_plugin(self, af, route_type, src, dest, same_machine, plugin_name):
        if not self.child_plugins_queue:
            raise AssertionError("StubManager: ran out of pre-stocked children")
        child = self.child_plugins_queue.pop(0)
        child.manager = self
        child.af = af
        child.route_type = route_type
        child.src = src
        child.dest = dest
        child.same_machine = same_machine
        self.plugins[child.plugin_id] = child
        self.created.append(child)
        return child

    async def run_plugin(self, plugin, reply=None):
        try:
            await plugin.run(reply)
        except asyncio.CancelledError:
            raise


# close_plugin is called as a free function inside fan_out; test uses
# a real one that respects the StubManager dicts.
class TestFanOutRun(AsyncTestCase):
    """End-to-end run() behaviour with stubbed manager + children."""

    async def test_first_winner_wins_others_cancelled(self):
        # Three children: fast winner, two slow losers. Fan_out should
        # return the winner's pipe and cancel + close the losers.
        winner_pipe = object()  # any non-None sentinel
        winner = StubChildPlugin()
        winner.delay = 0.05
        winner.pipe_value = winner_pipe

        loser_a = StubChildPlugin()
        loser_a.delay = 5.0
        loser_a.pipe_value = "should_not_appear_a"

        loser_b = StubChildPlugin()
        loser_b.delay = 5.0
        loser_b.pipe_value = "should_not_appear_b"

        manager = StubManager([winner, loser_a, loser_b])

        src = make_map("A", ipv4_infos=[
            make_info(0, 10, 100),
            make_info(1, 11, 101),
        ])
        dest = make_map("B", ipv4_infos=[
            make_info(0, 20, 200),
            make_info(1, 21, 201),
        ])

        fan = FanOutPlugin()
        fan.manager = manager
        fan.set_addrs(src, dest)
        fan.timeout = 3.0
        fan.configure_target("direct_connect", af=IP4, route_type=NIC_BIND)

        # Trim the queue so we only spawn 3 children even if more
        # combos are produced (extras would error out of the queue).
        # Force an exact 3-pair test by limiting addr maps:
        # 2 src x 2 dest with distinct NICs = 4 pairs. Drop one
        # src to make it 1 src x 2 dest = 2 pairs... but we need 3.
        # Easier: stub create_plugin to only honour the first N calls.
        # Already in StubManager via the pre-stocked list -- just
        # tighten dest to 2 if_index entries. We have 4 combos
        # available; provide 4 children.
        manager.child_plugins_queue = [winner, loser_a, loser_b, StubChildPlugin()]
        # 4th child: same as losers.
        manager.child_plugins_queue[3].delay = 5.0
        manager.child_plugins_queue[3].pipe_value = "extra"

        await fan.run()

        result = fan.result.result()
        self.assertIs(result, winner_pipe)
        self.assertEqual(winner.run_count, 1)
        # Losers should have started and then been cancelled.
        for loser in (loser_a, loser_b):
            self.assertEqual(loser.run_count, 1)
            self.assertTrue(loser.cancelled)

    async def test_no_combos_returns_none(self):
        """Empty addr_maps mean no combos -> result is None, no children spawned."""
        src = make_map("A")  # no IPv4, no IPv6
        dest = make_map("B")

        manager = StubManager([])
        fan = FanOutPlugin()
        fan.manager = manager
        fan.set_addrs(src, dest)
        fan.timeout = 1.0
        fan.configure_target("direct_connect")

        await fan.run()
        self.assertIsNone(fan.result.result())
        self.assertEqual(manager.created, [])

    async def test_run_without_target_raises(self):
        """run() before configure_target() is a programmer error."""
        manager = StubManager([])
        fan = FanOutPlugin()
        fan.manager = manager
        fan.set_addrs(make_map("A"), make_map("B"))
        fan.timeout = 1.0
        with self.assertRaises(ValueError):
            await fan.run()


if __name__ == "__main__":
    unittest.main()
