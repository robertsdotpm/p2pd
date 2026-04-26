"""
tests/test_punch_plugin.py

End-to-end bidirectional integration test for the PunchPlugin state machine.

Architecture
────────────
Two PunchPlugin instances (A and B) are wired through an in-process message
bus that replaces MQTT signaling.  The complete three-message handshake is
driven step-by-step:

  Step 1 – A.run(reply=None)     → PunchMsg(A's NAT mappings) ──► B
  Step 2 – B.run(reply=A's msg)  → PunchMsg(B's NAT mappings) ──► A
  Step 3 – A.run(reply=B's msg)  → is_end==1, protocol done

After the exchange both plugins schedule their punch subprocess via
delayed_start_punching_proc (2-second delay).  The subprocesses run
tcp_selector_punch_engine, which performs a TCP simultaneous-open between
IP_A and IP_B, then reverse-connects back to the parent via selector_proxy.
The result Future on each plugin is resolved to a Pipe wrapping the
reverse-connect socket.

Mocking / patching
───────────────────
• p2pd.traversal.plugins.tcp_punch.nat_predict.preload_mappings is patched to return
  synthetic NATMapping objects so no real STUN servers are needed.  The full
  NAT-prediction state machine (init_predictions, get_single_mapping,
  NATPredictAlloc.port_alloc) is exercised unchanged.
• MQTT signaling is replaced by asyncio.Queue objects routed directly between
  the two plugin instances.

The only real network activity is the TCP simultaneous-open between two NIC
IPs on the same machine (no external connectivity required).

Requirements
─────────────
• Linux (SO_REUSEPORT available)
• The active NIC must expose ≥ 2 private IPv4 addresses (skip otherwise)
• Python ≥ 3.8
"""

import asyncio
import copy
import socket
import sys
import time
import unittest
from concurrent.futures import ProcessPoolExecutor
from unittest.mock import patch

from aionetiface import (
    Interface,
    IP4,
    IP6,
    NIC_BIND,
    SysClock,
    async_wrap_errors,
    bind_closure,
    binder_async,
)

# NAT type / delta constants come from aionetiface via the star import
# in punch_defs; import them explicitly to avoid *-import ambiguity.
from aionetiface import (
    nat_info,
    delta_info,
    RESTRICT_PORT_NAT,
    EQUAL_DELTA,
)

from p2pd.traversal.plugins.tcp_punch.punch_defs import PUNCH_MAX_SLEEP
from p2pd.traversal.plugins.tcp_punch.nat_predict import NATMapping
from p2pd.traversal.plugins.tcp_punch.main import PunchPluginFactory
from p2pd.protocol.proto_msg import PunchMsg

from aionetiface.testing import make_fake_nic


from aionetiface.testing import AsyncTestCase


# ─────────────────────────────────────────────────────────────────────────────
# Fake STUN client
# ─────────────────────────────────────────────────────────────────────────────


class FakeStunClient:
    """
    Minimal STUN-client shim required by NATPredictAlloc.

    Only three attributes / one method are ever accessed:
      .af         – address family (used by NATPredictAlloc.__init__)
      .interface  – NIC object    (used by get_high_port_mapping)
      .conf       – dict          (reuse_addr assertion in get_high_port_mapping)
      .get_mapping(pipe) – async  (called by get_high_port_mapping)

    Note: get_high_port_mapping is patched out entirely, so get_mapping is
    never actually called in these tests.  The FakeStunClient is only needed
    so that NATPredictAlloc(stuns) can read stuns[0].af.
    """

    def __init__(self, nic, af):
        self.interface = nic
        self.af = af
        self.conf = {"reuse_addr": True}

    async def get_mapping(self, pipe=None):
        # Synthetic no-NAT mapping: local port == remote port.
        port = 32000
        return (port, port, None)


# ─────────────────────────────────────────────────────────────────────────────
# Fake preload_mappings
# ─────────────────────────────────────────────────────────────────────────────


async def _fake_preload_mappings(no, stuns):
    """
    Drop-in replacement for nat_predict.preload_mappings.

    Returns `no` synthetic NATMapping objects.  For TCP_PUNCH_LAN / OPEN_INTERNET
    NATs the preloaded values are not used in get_single_mapping (the function
    takes the rmap.remote branch instead), so the exact ports here do not
    affect the final port allocations produced by the protocol.
    """
    base = 32500
    return [NATMapping([base + i, 0, base + i]) for i in range(no)]


# ─────────────────────────────────────────────────────────────────────────────
# Main test class
# ─────────────────────────────────────────────────────────────────────────────


class TestPunchPluginBidirectional(AsyncTestCase):
    """
    Full-stack bidirectional punch integration test.

    Exercises (in order):
      1. PunchPlugin.run() state machine – three-message signaling exchange
      2. NATPredictAlloc port negotiation – LAN-mode NAT prediction on both sides
      3. delayed_start_punching_proc scheduling and 2-second coordination delay
      4. start_punching_process – listening pipe + ProcessPool subprocess spawn
      5. tcp_selector_punch_engine – TCP simultaneous-open between two NIC IPs
      6. selector_proxy reverse-connect from punch subprocess back to main process
      7. PunchPlugin.result Future resolution with a live Pipe object

    Skipped when the active NIC has fewer than two private IPv4 addresses.
    """

    # ── setup / teardown ─────────────────────────────────────────────────────

    async def asyncSetUp(self):
        self.nic = await Interface()

        if IP4 not in self.nic.supported():
            self.skipTest("IPv4 not available on this machine")

        r4 = self.nic.route(IP4)
        if len(r4.nic_ips) < 2:
            self.skipTest(
                "Need ≥ 2 NIC IPs for bidirectional punch plugin test "
                "(found: {})".format([str(ip) for ip in r4.nic_ips])
            )

        self.ip_a = str(r4.nic_ips[0].ip)
        self.ip_b = str(r4.nic_ips[1].ip)

        # Shared clock – seed from wall clock; no NTP probe needed for tests.
        self.sys_clock = SysClock(None, int(time.time()))

        # Two workers: one punch subprocess per side.
        self.proc_pool = ProcessPoolExecutor(max_workers=2)

        # stop_reader/stop_writer – socketpair so selector_proxy can poll it.
        # We never write to stop_w, so the proxy runs until one side closes.
        # socketpair objects are reduceable by multiprocessing.reduction on Linux,
        # allowing them to be pickled into the ProcessPoolExecutor workers.
        self.stop_r, self.stop_w = socket.socketpair()
        self.stop_r.setblocking(False)

        self._plugins = []

    async def asyncTearDown(self):
        # Cancel pending punch-process tasks.
        for plugin in self._plugins:
            if not plugin.result.done():
                plugin.result.cancel()
            for task in list(plugin.punch_proc.values()):
                if not task.done():
                    task.cancel()
            # Let cancelled tasks settle.
            await asyncio.gather(
                *[t for t in plugin.punch_proc.values()],
                return_exceptions=True,
            )

        self.proc_pool.shutdown(wait=False)

        for s in (self.stop_r, self.stop_w):
            try:
                s.close()
            except Exception:
                pass

    # ── helpers ──────────────────────────────────────────────────────────────

    def _make_addr_info(self, ip, if_index=0):
        """
        Build a minimal src_info / dest_info dict for use by:
          • TraversalPlugin.set_routing()
          • TraversalPlugin.set_context() → select_dest_ipr()
          • PunchPlugin.setup_puncher_client() → NATPredictAlloc.set_nat_info()
        """
        return {
            "if_index": if_index,
            # netiface_index drives same_if detection in select_dest_ipr.
            # Both sides share index 0 (same physical NIC, different IPs).
            "netiface_index": 0,
            # For NIC_BIND + same_machine=True, select_dest_ipr returns
            # dest_info["nic"].  ext is compared only for EXT_BIND.
            "ext": ip,
            "nic": ip,
            "nat": nat_info(RESTRICT_PORT_NAT, delta_info(EQUAL_DELTA, 0)),
            "port": 3000,
        }

    def _build_plugin(self, src_ip, dest_ip, nic=None):
        """
        Instantiate and configure a PunchPlugin for src_ip → dest_ip.

        Each call creates an independent PunchPluginFactory with its own
        punch_clients and punch_proc dicts, mirroring the real-world setup
        where A and B are separate nodes.

        Pass a fake NIC (via make_fake_nic) when you need setup_puncher_client
        to use a specific secondary IP for route().nic().  The real NIC is used
        by default (which returns the primary IP).
        """
        effective_nic = nic or self.nic

        fake_stun = FakeStunClient(effective_nic, IP4)
        # stun_clients[af][if_index] = list of STUN clients
        stun_table = {IP4: {0: [fake_stun]}}

        factory = PunchPluginFactory(
            stun_clients=stun_table,
            punch_clients={},  # per-factory, not shared across sides
            sys_clock=self.sys_clock,
            proc_pool=self.proc_pool,
        )
        plugin = factory.build_plugin()

        # stop_reader is passed into the punch subprocess for proxy termination.
        plugin.stop_reader = self.stop_r

        src_info = self._make_addr_info(src_ip)
        dest_info = self._make_addr_info(dest_ip)

        # set_routing stores af / src_info / dest_info / nic on the plugin.
        # The NIC is also used by start_punching_process to create the listen
        # socket for the reverse-connect from the punch subprocess.
        plugin.set_routing(IP4, src_info, dest_info, effective_nic)

        # set_context runs select_dest_ipr → sets dest_info["ip"] = dest_ip.
        plugin.set_context(
            route_type=NIC_BIND,
            same_machine=True,
            set_bind=True,
            timeout=60,  # generous timeout; actual punch takes ~10 s
        )

        self._plugins.append(plugin)
        return plugin

    # ── main test ─────────────────────────────────────────────────────────────

    async def test_full_plugin_sequence_bidirectional_punch(self):
        """
        Run the complete punch-plugin lifecycle end-to-end on both sides.

        Protocol walk-through
        ─────────────────────
        A.run(None)        – initiator: creates PunchClient, builds NAT
                             mappings via NATPredictAlloc (LAN mode), sends
                             PunchMsg carrying its port predictions to B.

        B.run(reply=A_msg) – recipient: creates its own PunchClient, uses
                             A's mappings as recv_mappings to drive its NAT
                             prediction, sends PunchMsg carrying B's ports to A.

        A.run(reply=B_msg) – A advances state machine: UPDATED_PREDICTIONS
                             (is_end==1) → returns None (no further message).

        Both sides schedule delayed_start_punching_proc after their first
        configure_puncher_process call.  Two seconds later each side spawns a
        punch subprocess that runs tcp_selector_punch_engine.  The engine
        sleeps until the shared punch_time, then fires simultaneous SYNs:

            IP_A:P  ──SYN──►  IP_B:P
            IP_A:P  ◄──SYN──  IP_B:P   (simultaneous-open)

        On success each subprocess reverse-connects back to a listen socket
        in the main process (selector_proxy), resolving plugin.result with
        the reverse-connect Pipe.

        Validation
        ──────────
        • All three outgoing message counts / types are asserted.
        • Port allocations are verified to be symmetric (both sides use the
          same port P, enabling the simultaneous-open).
        • Both result Futures resolve within 30 seconds.
        • The returned Pipe wraps a live socket whose peer address is the
          opposing NIC IP.
        """
        ip_a, ip_b = self.ip_a, self.ip_b
        print("\n\nBidirectional PunchPlugin test: {} ↔ {}".format(ip_a, ip_b))

        # Build the two independent plugin instances.
        # Plugin A uses the real NIC (primary IP = ip_a).
        # Plugin B uses a fake NIC wrapper that reports ip_b as its NIC IP so
        # that setup_puncher_client → route.nic() returns ip_b, not ip_a.
        # Without this, both sides would bind to the primary NIC IP and the
        # simultaneous-open would be a meaningless self-loop.
        r4 = self.nic.route(IP4)
        nic_b = make_fake_nic(self.nic, IP4, r4.nic_ips[1])

        plugin_a = self._build_plugin(src_ip=ip_a, dest_ip=ip_b)
        plugin_b = self._build_plugin(src_ip=ip_b, dest_ip=ip_a, nic=nic_b)

        # B must share A's pipe_id so the three-message state machine pairs
        # them up correctly.  In the real system this is done by
        # TraversalManager.get_plugin() when the first message arrives at B.
        plugin_b.set_inbound_pipes({}, plugin_id=plugin_a.plugin_id)

        # ── in-process message router ─────────────────────────────────────
        # Each plugin's send_signal_msg writes into a queue; the test loop
        # reads from the queues and delivers messages to the other plugin.
        msgs_for_b = asyncio.Queue()
        msgs_for_a = asyncio.Queue()

        async def sender_a(msg, plugin, relay_no=2):
            """A sends → captured for delivery to B."""
            await msgs_for_b.put(msg)

        async def sender_b(msg, plugin, relay_no=2):
            """B sends → captured for delivery to A."""
            await msgs_for_a.put(msg)

        plugin_a.set_send_signal_msg(sender_a)
        plugin_b.set_send_signal_msg(sender_b)

        # ── three-message handshake ───────────────────────────────────────
        # preload_mappings is patched to avoid real STUN connections while
        # keeping the full NATPredictAlloc state machine intact.
        with patch(
            "p2pd.traversal.plugins.tcp_punch.nat_predict.preload_mappings",
            side_effect=_fake_preload_mappings,
        ):
            # ── Step 1: A initiates ──────────────────────────────────────
            print("  [Step 1] A.run(None) → should produce PunchMsg …")
            await async_wrap_errors(plugin_a.run(reply=None))

            msg_a = await asyncio.wait_for(msgs_for_b.get(), timeout=10)

            self.assertIsNotNone(msg_a, "Plugin A must produce an outgoing PunchMsg")
            self.assertIsInstance(
                msg_a, PunchMsg, "Outgoing message from A must be a PunchMsg"
            )
            self.assertTrue(
                len(msg_a.payload.mappings) > 0,
                "Plugin A's PunchMsg must carry at least one mapping",
            )
            print(
                "  [Step 1] ✓  A produced PunchMsg with {} mapping(s)".format(
                    len(msg_a.payload.mappings)
                )
            )

            # Sanity: A's punch process task has been scheduled.
            self.assertIn(
                plugin_a.plugin_id,
                plugin_a.punch_proc,
                "Plugin A's delayed punch task should be scheduled after step 1",
            )

            # ── Step 2: B responds ───────────────────────────────────────
            print("  [Step 2] B.run(reply=A_msg) → should produce PunchMsg …")
            await async_wrap_errors(plugin_b.run(reply=msg_a))

            msg_b = await asyncio.wait_for(msgs_for_a.get(), timeout=10)

            self.assertIsNotNone(msg_b, "Plugin B must produce a reply PunchMsg")
            self.assertIsInstance(
                msg_b, PunchMsg, "Outgoing message from B must be a PunchMsg"
            )
            self.assertTrue(
                len(msg_b.payload.mappings) > 0,
                "Plugin B's PunchMsg must carry at least one mapping",
            )
            print(
                "  [Step 2] ✓  B produced PunchMsg with {} mapping(s)".format(
                    len(msg_b.payload.mappings)
                )
            )

            # Sanity: B's punch process task has been scheduled.
            self.assertIn(
                plugin_a.plugin_id,
                plugin_b.punch_proc,
                "Plugin B's delayed punch task should be scheduled after step 2",
            )

            # ── Step 3: A finalises (is_end == 1) ───────────────────────
            print("  [Step 3] A.run(reply=B_msg) → protocol should terminate …")
            await async_wrap_errors(plugin_a.run(reply=msg_b))

            # A must NOT send another message (is_end flag terminates protocol).
            self.assertTrue(
                msgs_for_b.empty(),
                "Plugin A must not send a fourth message after is_end==1",
            )
            print("  [Step 3] ✓  A finalised – no further message sent")

        # ── port-allocation symmetry check ────────────────────────────────
        # Both punchers operate in TCP_PUNCH_LAN mode (private dest IP +
        # NATPredictAlloc.same_machine=False by design).  In LAN mode the NAT
        # types are patched to OPEN_INTERNET, so get_single_mapping returns
        # NATMapping([rmap.remote, 0, rmap.remote]) for both sides.  B uses
        # A's mapping as rmap, so both sides end up with the same port P:
        #
        #   A: PortAlloc(src=P, dest=P)  →  bind IP_A:P, connect IP_B:P
        #   B: PortAlloc(src=P, dest=P)  →  bind IP_B:P, connect IP_A:P
        #
        # This is the symmetric simultaneous-open required for TCP hole-punch.
        puncher_a = plugin_a.punch_clients.get(plugin_a.plugin_id)
        puncher_b = plugin_b.punch_clients.get(plugin_a.plugin_id)  # shared pipe_id

        self.assertIsNotNone(puncher_a, "Plugin A must have a stored PunchClient")
        self.assertIsNotNone(puncher_b, "Plugin B must have a stored PunchClient")
        self.assertTrue(
            len(puncher_a.port_allocs) > 0,
            "Plugin A's PunchClient must have port allocations",
        )
        self.assertTrue(
            len(puncher_b.port_allocs) > 0,
            "Plugin B's PunchClient must have port allocations",
        )

        # Both sides must agree on the same destination port for each pair
        # so that the cross-SYNs land at listening sockets.
        ports_a = {alloc.dest_port for alloc in puncher_a.port_allocs}
        ports_b = {alloc.dest_port for alloc in puncher_b.port_allocs}
        shared_ports = ports_a & ports_b
        self.assertTrue(
            len(shared_ports) > 0,
            "A and B must share at least one agreed port for simultaneous-open "
            "(A dest ports: {}, B dest ports: {})".format(ports_a, ports_b),
        )
        print("  Agreed simultaneous-open port(s): {}".format(shared_ports))

        # Verify punch_time agreement (both used the same sys_clock seed).
        self.assertEqual(
            puncher_a.punch_time,
            puncher_b.punch_time,
            "Both sides must agree on the punch_time (computed from same clock seed)",
        )
        print("  Punch time: {} (both sides agree)".format(puncher_a.punch_time))

        # ── wait for punch results ────────────────────────────────────────
        # Timeline from here:
        #   +0 s   – delayed_start_punching_proc sleeping (asyncio.sleep(2))
        #   +2 s   – start_punching_process creates listen socket + spawns proc
        #   +2 s   – subprocess starts, calls sleep_until() (≤ PUNCH_MAX_SLEEP=3 s)
        #   +5 s   – both subprocesses fire simultaneous SYNs
        #   +5 s   – socket_event_monitor (CONNECT_TIMEOUT=5 s)
        #   +10 s  – reverse-connect completes; result Futures resolved
        # 30-second timeout leaves 20 seconds of slack.
        print("  Waiting for punch result Futures (≤ 30 s) …")

        try:
            result_a, result_b = await asyncio.wait_for(
                asyncio.gather(
                    asyncio.shield(plugin_a.result),
                    asyncio.shield(plugin_b.result),
                ),
                timeout=30,
            )
        except asyncio.TimeoutError:
            self.fail(
                "Punch result Futures did not resolve within 30 s.\n"
                "Check that the machine allows TCP simultaneous-open on "
                "loopback/LAN addresses and that no host firewall blocks "
                "the agreed ports: {}".format(shared_ports)
            )

        # ── result validation ─────────────────────────────────────────────
        print("\n  Result A: {}".format(result_a))
        print("  Result B: {}".format(result_b))

        # On a local machine with no NAT both sides should succeed.
        # The stronger assertion comes first so the failure message is clear.
        self.assertIsNotNone(
            result_a,
            "Plugin A punch must succeed on a local machine (got None)",
        )
        self.assertIsNotNone(
            result_b,
            "Plugin B punch must succeed on a local machine (got None)",
        )

        # Inspect the reverse-connect pipe returned to each side.
        for label, result, expected_peer_ip in [
            ("A", result_a, ip_b),
            ("B", result_b, ip_a),
        ]:
            if result is None:
                continue
            try:
                # result is a Pipe whose .sock is the reverse-connect socket.
                # The reverse-connect socket connects back to the main process,
                # so its peer is the listen socket bound to src_ip of that side.
                # (peer == src_ip of the plugin that spawned this subprocess)
                sock = result.sock
                local = sock.getsockname()
                peer = sock.getpeername()
                print(
                    "  {} pipe: local={}:{} → peer={}:{}".format(
                        label, local[0], local[1], peer[0], peer[1]
                    )
                )
            except Exception as e:
                print("  {} pipe socket info error: {}".format(label, e))

        print("\n  ✓ Bidirectional PunchPlugin integration test passed.")


# ─────────────────────────────────────────────────────────────────────────────
# IPv6 link-local fake NIC helper
# ─────────────────────────────────────────────────────────────────────────────


def make_fake_nic_v6(real_nic, target_ll_ipr):
    """
    Fake NIC for IPv6 link-local punch tests.

    Extends make_fake_nic by also overriding route.link_locals so that
    setup_puncher_client's ``src_ip = str(route.link_locals[0])`` returns
    *target_ll_ipr* instead of the NIC's actual primary link-local address.

    For global (non-fe80) destinations setup_puncher_client falls back to
    route.nic(), which is driven by nic_ips.  Both are overridden here so
    the fake NIC works for either code path.
    """

    class FakeNICv6:
        __name__ = "FakeNICv6"

        def __init__(self):
            self.name = real_nic.name
            self.id = getattr(real_nic, "id", 0)

        def route(self, req_af=None):
            r = copy.deepcopy(real_nic.route(IP6))
            r.nic_ips = [target_ll_ipr]
            r.link_locals = [target_ll_ipr]
            r.resolved = False
            r.interface = _instance
            r.bind = bind_closure(r, binder_async)
            return r

        def supported(self):
            return [IP6]

    _instance = FakeNICv6()
    return _instance


# ─────────────────────────────────────────────────────────────────────────────
# IPv6 link-local punch plugin test
# ─────────────────────────────────────────────────────────────────────────────


class TestPunchPluginIPv6LinkLocal(AsyncTestCase):
    """
    Bidirectional PunchPlugin integration test using IPv6 link-local (fe80) addresses.

    Exercises the same three-message handshake as TestPunchPluginBidirectional
    but specifically targets the fe80 code path in setup_puncher_client:

        if "fe80" == dest_ip[:4]:
            src_ip = str(route.link_locals[0])   # <-- this branch

    This verifies that:
      1. scope IDs (%ens34) flow correctly through ip_norm / patch_connect_ip
      2. the fake NIC's link_locals override is picked up by setup_puncher_client
      3. the complete signaling exchange and port-allocation symmetry hold for IPv6

    Skipped when the active NIC has fewer than two link-local IPv6 addresses.
    """

    async def asyncSetUp(self):
        self.nic = await Interface()

        if IP6 not in self.nic.supported():
            self.skipTest("IPv6 not available on this machine")

        r6 = self.nic.route(IP6)
        link_locals = r6.link_locals

        if len(link_locals) < 2:
            self.skipTest(
                "Need ≥ 2 link-local IPv6 addresses for bidirectional link-local "
                "punch test (found: {})".format([str(ip) for ip in link_locals])
            )

        self.ll_a = link_locals[0]  # IPRange
        self.ll_b = link_locals[1]  # IPRange
        self.nic_id = self.nic.id

        self.sys_clock = SysClock(None, int(time.time()))
        self.proc_pool = ProcessPoolExecutor(max_workers=2)
        self.stop_r, self.stop_w = socket.socketpair()
        self.stop_r.setblocking(False)
        self._plugins = []

    async def asyncTearDown(self):
        for plugin in self._plugins:
            if not plugin.result.done():
                plugin.result.cancel()
            for task in list(plugin.punch_proc.values()):
                if not task.done():
                    task.cancel()
            await asyncio.gather(
                *[t for t in plugin.punch_proc.values()],
                return_exceptions=True,
            )

        self.proc_pool.shutdown(wait=False)

        for s in (self.stop_r, self.stop_w):
            try:
                s.close()
            except Exception:
                pass

    # ── helpers ──────────────────────────────────────────────────────────────

    def _make_addr_info_v6(self, ip_ipr, if_index=0):
        """
        Build src_info / dest_info for an IPv6 link-local address.

        The "nic" field carries the scoped address (fe80::...%ens34) so that
        select_dest_ipr returns the scoped string as dest_info["ip"].
        setup_puncher_client then feeds this to PunchClient.__init__ which
        calls ip_norm (strips %) and patch_connect_ip (re-adds %) before use.
        """
        ip_bare = str(ip_ipr.ip)  # "fe80::xxx"  (no scope)
        ip_scoped = "{}%{}".format(ip_bare, self.nic_id)  # "fe80::xxx%ens34"
        return {
            "if_index": if_index,
            "netiface_index": 0,
            "ext": ip_bare,
            "nic": ip_scoped,
            "nat": nat_info(RESTRICT_PORT_NAT, delta_info(EQUAL_DELTA, 0)),
            "port": 3000,
        }

    def _build_plugin_v6(self, src_ll_ipr, dest_ll_ipr, nic=None):
        """
        Instantiate a PunchPlugin configured for IPv6 link-local addresses.
        """
        effective_nic = nic or self.nic

        fake_stun = FakeStunClient(effective_nic, IP6)
        stun_table = {IP6: {0: [fake_stun]}}

        factory = PunchPluginFactory(
            stun_clients=stun_table,
            punch_clients={},
            sys_clock=self.sys_clock,
            proc_pool=self.proc_pool,
        )
        plugin = factory.build_plugin()
        plugin.stop_reader = self.stop_r

        src_info = self._make_addr_info_v6(src_ll_ipr)
        dest_info = self._make_addr_info_v6(dest_ll_ipr)

        plugin.set_routing(IP6, src_info, dest_info, effective_nic)
        plugin.set_context(
            route_type=NIC_BIND,
            same_machine=True,
            set_bind=True,
            timeout=60,
        )

        self._plugins.append(plugin)
        return plugin

    # ── main test ─────────────────────────────────────────────────────────────

    async def test_full_plugin_sequence_ipv6_link_local(self):
        """
        Three-message punch-plugin handshake over IPv6 link-local addresses.

        Plugin A uses the real NIC's first link-local (ll_a); a fake NIC
        wrapper overrides link_locals to return ll_b for plugin B so that
        setup_puncher_client → route.link_locals[0] picks the right address
        on each side.
        """
        ip_a_str = str(self.ll_a.ip)
        ip_b_str = str(self.ll_b.ip)
        print(
            "\n\nIPv6 Link-Local PunchPlugin test: {}%{} ↔ {}%{}".format(
                ip_a_str, self.nic_id, ip_b_str, self.nic_id
            )
        )

        # Plugin A – real NIC, link_locals[0] = ll_a (natural).
        # Plugin B – fake NIC that overrides link_locals to return ll_b.
        nic_b = make_fake_nic_v6(self.nic, self.ll_b)

        plugin_a = self._build_plugin_v6(src_ll_ipr=self.ll_a, dest_ll_ipr=self.ll_b)
        plugin_b = self._build_plugin_v6(
            src_ll_ipr=self.ll_b, dest_ll_ipr=self.ll_a, nic=nic_b
        )

        plugin_b.set_inbound_pipes({}, plugin_id=plugin_a.plugin_id)

        msgs_for_b = asyncio.Queue()
        msgs_for_a = asyncio.Queue()

        async def sender_a(msg, plugin=None, relay_no=2):
            await msgs_for_b.put(msg)

        async def sender_b(msg, plugin=None, relay_no=2):
            await msgs_for_a.put(msg)

        plugin_a.set_send_signal_msg(sender_a)
        plugin_b.set_send_signal_msg(sender_b)

        with patch(
            "p2pd.traversal.plugins.tcp_punch.nat_predict.preload_mappings",
            side_effect=_fake_preload_mappings,
        ):
            # Step 1 – A initiates
            print("  [Step 1] A.run(None) …")
            await async_wrap_errors(plugin_a.run(reply=None))

            msg_a = await asyncio.wait_for(msgs_for_b.get(), timeout=10)
            self.assertIsNotNone(msg_a)
            self.assertIsInstance(msg_a, PunchMsg)
            self.assertTrue(len(msg_a.payload.mappings) > 0)
            print(
                "  [Step 1] ✓  A produced PunchMsg ({} mapping(s))".format(
                    len(msg_a.payload.mappings)
                )
            )

            # Step 2 – B responds
            print("  [Step 2] B.run(reply=A_msg) …")
            await async_wrap_errors(plugin_b.run(reply=msg_a))

            msg_b = await asyncio.wait_for(msgs_for_a.get(), timeout=10)
            self.assertIsNotNone(msg_b)
            self.assertIsInstance(msg_b, PunchMsg)
            self.assertTrue(len(msg_b.payload.mappings) > 0)
            print(
                "  [Step 2] ✓  B produced PunchMsg ({} mapping(s))".format(
                    len(msg_b.payload.mappings)
                )
            )

            # Step 3 – A finalises
            print("  [Step 3] A.run(reply=B_msg) …")
            await async_wrap_errors(plugin_a.run(reply=msg_b))
            self.assertTrue(msgs_for_b.empty(), "No fourth message expected")
            print("  [Step 3] ✓  A finalised – no further message sent")

        # ── port-allocation symmetry ──────────────────────────────────────────
        puncher_a = plugin_a.punch_clients.get(plugin_a.plugin_id)
        puncher_b = plugin_b.punch_clients.get(plugin_a.plugin_id)

        self.assertIsNotNone(puncher_a)
        self.assertIsNotNone(puncher_b)

        ports_a = {alloc.dest_port for alloc in puncher_a.port_allocs}
        ports_b = {alloc.dest_port for alloc in puncher_b.port_allocs}
        shared_ports = ports_a & ports_b
        self.assertTrue(
            len(shared_ports) > 0,
            "A and B must share ≥ 1 agreed port (A={}, B={})".format(ports_a, ports_b),
        )
        print("  Agreed port(s): {}".format(shared_ports))

        self.assertEqual(
            puncher_a.punch_time,
            puncher_b.punch_time,
            "Both sides must agree on punch_time",
        )

        # ── verify fe80 scope IDs were applied correctly ──────────────────────
        # PunchClient.__init__ calls ip_norm (strips %) then patch_connect_ip
        # (re-adds %nic_id).  After that, puncher.dest_ip must be "ip%nic_id".
        expected_dest_a = "{}%{}".format(ip_b_str, self.nic_id)
        expected_dest_b = "{}%{}".format(ip_a_str, self.nic_id)
        self.assertEqual(
            puncher_a.dest_ip,
            expected_dest_a,
            "Plugin A: dest_ip must carry scope ID (got {!r})".format(
                puncher_a.dest_ip
            ),
        )
        self.assertEqual(
            puncher_b.dest_ip,
            expected_dest_b,
            "Plugin B: dest_ip must carry scope ID (got {!r})".format(
                puncher_b.dest_ip
            ),
        )
        print("  A dest_ip: {}  (scope correct)".format(puncher_a.dest_ip))
        print("  B dest_ip: {}  (scope correct)".format(puncher_b.dest_ip))

        # ── wait for punch results ────────────────────────────────────────────
        print("  Waiting for punch result Futures (≤ 30 s) …")
        try:
            result_a, result_b = await asyncio.wait_for(
                asyncio.gather(
                    asyncio.shield(plugin_a.result),
                    asyncio.shield(plugin_b.result),
                ),
                timeout=30,
            )
        except asyncio.TimeoutError:
            self.fail(
                "Punch result Futures did not resolve within 30 s. "
                "Agreed ports: {}".format(shared_ports)
            )

        print("\n  Result A: {}".format(result_a))
        print("  Result B: {}".format(result_b))

        self.assertIsNotNone(result_a, "Plugin A punch must succeed")
        self.assertIsNotNone(result_b, "Plugin B punch must succeed")

        for label, result in [("A", result_a), ("B", result_b)]:
            if result is None:
                continue
            try:
                sock = result.sock
                local = sock.getsockname()
                peer = sock.getpeername()
                print("  {} pipe: local={} → peer={}".format(label, local, peer))
            except Exception as e:
                print("  {} pipe socket info error: {}".format(label, e))

        print("\n  ✓ IPv6 link-local PunchPlugin integration test passed.")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
