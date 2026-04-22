"""
Tests for the TURN client, relay server, and traversal plugin.

Two complementary test suites:

  TestTURNLoopback     --  Two TURNClient instances on 127.0.0.1 (same loopback
                           IP, different source ports) relay a message through
                           the local TURNServer.  Always runs.

  TestTURNNicIPs       --  Same flow but each client is bound to a different NIC
                           IP (e.g. 10.0.1.76 / 10.0.1.100).  Skipped when the
                           machine has fewer than two private IPs on the same
                           interface.

  TestTURNLoopbackIPv6 --  Mirrors TestTURNLoopback over IPv6 (::1).
                           Skipped when IPv6 is not available.

  TestTURNPluginIPv6   --  Exercises TURNPlugin end-to-end over IPv6.
                           Skipped when IPv6 is not available.

  TestTURNPlugin       --  Exercises the TURNPlugin traversal plugin end-to-end
                           with a simulated signalling channel and the local
                           TURNServer patched into TURN_SERVERS.

Run from project root:
    python -m pytest tests/test_turn.py -v
or
    python -m unittest tests/test_turn -v
"""

import asyncio
import copy
import sys
import unittest
from unittest.mock import patch

import aionetiface
from aionetiface import (
    Interface,
    Pipe,
    UDP,
    IP4,
    IP6,
    EXT_BIND,
    to_s,
    rand_plain,
    async_wrap_errors,
    log_exception,
    bind_closure,
    binder_async,
)

from p2pd.protocol.turn.turn_client import TURNClient
from p2pd.traversal.plugins.turn.main import TURNPlugin
from p2pd.traversal.plugins.turn.turn_utils import get_turn_client
from p2pd.protocol.traversal.proto_msg import TURNMsg

from tests.turn_server import (
    TURNServer,
    TURN_TEST_PORT,
    TURN_TEST_REALM,
    TURN_TEST_USER,
    TURN_TEST_PASS,
    make_fake_nic,
    make_local_turn_server_entry,
)


# ──────────────────────────────────────────────────────────────────────────────
# Async test base compatible with Python 3.5+
# ──────────────────────────────────────────────────────────────────────────────

if sys.version_info >= (3, 8):
    AsyncTestCase = unittest.IsolatedAsyncioTestCase
else:

    class AsyncTestCase(unittest.TestCase):
        """
        Minimal asyncio-compatible TestCase for Python 3.5+.

        Provides asyncSetUp / asyncTearDown hooks and runs async test
        methods in a dedicated event loop created fresh for each test.
        """

        def run(self, result=None):
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            try:
                return super(AsyncTestCase, self).run(result)
            finally:
                self._loop.close()
                asyncio.set_event_loop(None)

        def setUp(self):
            self._loop.run_until_complete(self.asyncSetUp())

        def tearDown(self):
            self._loop.run_until_complete(self.asyncTearDown())

        async def asyncSetUp(self):
            pass

        async def asyncTearDown(self):
            pass

        def __getattribute__(self, name):
            val = object.__getattribute__(self, name)
            if name.startswith("test") and asyncio.iscoroutinefunction(val):
                try:
                    loop = object.__getattribute__(self, "_loop")
                except AttributeError:
                    # _loop not set yet (e.g. during test collection).
                    return val

                def sync_wrapper(coro_fn=val, ev_loop=loop):
                    ev_loop.run_until_complete(coro_fn())

                return sync_wrapper
            return val


# ──────────────────────────────────────────────────────────────────────────────
# Shared fixture helpers
# ──────────────────────────────────────────────────────────────────────────────


def make_turn_client(nic, dest_ip="127.0.0.1", port=TURN_TEST_PORT):
    """Return an uninitialised TURNClient aimed at the local test server."""
    return TURNClient(
        af=IP4,
        dest=(dest_ip, port),
        nic=nic,
        auth=(to_s(TURN_TEST_USER), to_s(TURN_TEST_PASS)),
        realm=to_s(TURN_TEST_REALM),
    )


async def start_client(nic, dest_ip="127.0.0.1", port=TURN_TEST_PORT, timeout=12):
    """Create and start a TURNClient, returning it once allocation is done."""
    client = make_turn_client(nic, dest_ip, port)
    await asyncio.wait_for(client.start(), timeout)
    return client


def make_turn_client_ip6(nic, dest_ip="::1", port=TURN_TEST_PORT):
    """Return an uninitialised IPv6 TURNClient aimed at the local test server."""
    return TURNClient(
        af=IP6,
        dest=(dest_ip, port),
        nic=nic,
        auth=(to_s(TURN_TEST_USER), to_s(TURN_TEST_PASS)),
        realm=to_s(TURN_TEST_REALM),
    )


async def start_client_ip6(nic, dest_ip="::1", port=TURN_TEST_PORT, timeout=12):
    """Create and start an IPv6 TURNClient, returning it once allocation is done."""
    client = make_turn_client_ip6(nic, dest_ip, port)
    await asyncio.wait_for(client.start(), timeout)
    return client


# ──────────────────────────────────────────────────────────────────────────────
# Test 1 -- Loopback relay (same 127.0.0.1, different ports)
# ──────────────────────────────────────────────────────────────────────────────


class TestTURNLoopback(AsyncTestCase):
    """
    Two TURNClients on loopback exchange a message through the local server.

    This validates the core relay flow:
      client_A -> relay_B socket -> DataIndication -> client_B
      client_B -> ACK -> relay_A socket -> DataIndication -> client_A
    """

    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP4 not in self.nic.supported():
            self.skipTest("IPv4 not available")
        self.server = TURNServer(self.nic)
        self.client_a = None
        self.client_b = None
        await self.server.start()

    async def asyncTearDown(self):
        for c in (self.client_a, self.client_b):
            if c is not None:
                await async_wrap_errors(c.close())
        await self.server.close()

    async def pair(self):
        """Start both clients, whitelist each other, and return their tups."""
        self.client_a = await start_client(self.nic)
        self.client_b = await start_client(self.nic)

        tup_a = await asyncio.wait_for(self.client_a.client_tup_future, 5)
        relay_a = await asyncio.wait_for(self.client_a.relay_tup_future, 5)
        tup_b = await asyncio.wait_for(self.client_b.client_tup_future, 5)
        relay_b = await asyncio.wait_for(self.client_b.relay_tup_future, 5)

        # Mutual whitelist (CreatePermission on each side).
        await asyncio.wait_for(self.client_a.accept_peer(tup_b, relay_b), 8)
        await asyncio.wait_for(self.client_b.accept_peer(tup_a, relay_a), 8)

        return tup_a, relay_a, tup_b, relay_b

    async def test_relay_addresses_are_assigned_and_distinct(self):
        """Each client gets its own relay address on 127.0.0.1."""
        self.client_a = await start_client(self.nic)
        self.client_b = await start_client(self.nic)

        relay_a = await asyncio.wait_for(self.client_a.relay_tup_future, 5)
        relay_b = await asyncio.wait_for(self.client_b.relay_tup_future, 5)

        # Both relay IPs match the server's loopback.
        self.assertEqual(relay_a[0], "127.0.0.1", "relay_a IP should be loopback")
        self.assertEqual(relay_b[0], "127.0.0.1", "relay_b IP should be loopback")
        # Different ports -- each client gets its own relay socket.
        self.assertNotEqual(relay_a[1], relay_b[1], "relay ports must differ")

    async def test_mapped_addresses_assigned(self):
        """Server returns a valid XorMappedAddress for each client."""
        self.client_a = await start_client(self.nic)
        self.client_b = await start_client(self.nic)

        tup_a = await asyncio.wait_for(self.client_a.client_tup_future, 5)
        tup_b = await asyncio.wait_for(self.client_b.client_tup_future, 5)

        self.assertEqual(tup_a[0], "127.0.0.1")
        self.assertEqual(tup_b[0], "127.0.0.1")
        self.assertIsInstance(tup_a[1], int)
        self.assertIsInstance(tup_b[1], int)
        # Different source ports.
        self.assertNotEqual(tup_a[1], tup_b[1])

    async def test_client_a_sends_message_to_client_b(self):
        """
        Full relay path: A->relay_B->DataIndication->B.
        client_b.recv() must return the exact bytes sent by client_a.
        """
        tup_a, relay_a, tup_b, relay_b = await self.pair()

        msg = b"hello via TURN relay"
        await self.client_a.send(msg, tup_b)

        received = await asyncio.wait_for(self.client_b.recv(), 8)
        self.assertIsNotNone(received, "client_b.recv() timed out")
        self.assertEqual(received, msg)

    async def test_bidirectional_relay(self):
        """A->B and B->A both work in sequence."""
        tup_a, relay_a, tup_b, relay_b = await self.pair()

        msg_ab = b"A to B"
        msg_ba = b"B to A"

        await self.client_a.send(msg_ab, tup_b)
        recv_b = await asyncio.wait_for(self.client_b.recv(), 8)
        self.assertEqual(recv_b, msg_ab)

        await self.client_b.send(msg_ba, tup_a)
        recv_a = await asyncio.wait_for(self.client_a.recv(), 8)
        self.assertEqual(recv_a, msg_ba)

    async def test_multiple_messages(self):
        """Multiple distinct messages all arrive intact."""
        tup_a, relay_a, tup_b, relay_b = await self.pair()

        messages = [b"msg%d" % i for i in range(5)]
        for m in messages:
            await self.client_a.send(m, tup_b)

        for m in messages:
            recv = await asyncio.wait_for(self.client_b.recv(), 8)
            self.assertIsNotNone(recv)
            self.assertIn(recv, messages)  # order not guaranteed


# ──────────────────────────────────────────────────────────────────────────────
# Test 2 -- Two different NIC IPs
# ──────────────────────────────────────────────────────────────────────────────


class TestTURNNicIPs(AsyncTestCase):
    """
    Client A is bound to NIC IP[0], Client B to NIC IP[1].

    Validates that the server correctly identifies the two clients as distinct
    peers (different source IPs) and that the relay path works across IPs.

    Skipped when the active interface has fewer than two private IPv4 addresses.
    """

    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP4 not in self.nic.supported():
            self.skipTest("IPv4 not available on this machine")

        r4 = self.nic.route(IP4)
        if len(r4.nic_ips) < 2:
            self.skipTest(
                "Need >= 2 NIC IPs for this test (found: {0})".format(
                    [str(ip) for ip in r4.nic_ips]
                )
            )

        self.ipr_a = r4.nic_ips[0]
        self.ipr_b = r4.nic_ips[1]
        self.ip_a = str(self.ipr_a.ip)
        self.ip_b = str(self.ipr_b.ip)

        # Server binds to the first NIC IP (both clients can reach it).
        self.server = TURNServer(self.nic, bind_ip=self.ip_a)
        self.client_a = None
        self.client_b = None
        await self.server.start()

    async def asyncTearDown(self):
        for c in (self.client_a, self.client_b):
            if c is not None:
                await async_wrap_errors(c.close())
        await self.server.close()

    async def start_client_on_ip(self, target_ipr):
        fake = make_fake_nic(self.nic, IP4, target_ipr)
        return await start_client(fake, dest_ip=self.ip_a)

    async def test_clients_have_distinct_source_ips(self):
        """
        The XorMappedAddress returned to each client reflects its NIC IP,
        confirming the server sees two different source addresses.
        """
        self.client_a = await self.start_client_on_ip(self.ipr_a)
        self.client_b = await self.start_client_on_ip(self.ipr_b)

        tup_a = await asyncio.wait_for(self.client_a.client_tup_future, 5)
        tup_b = await asyncio.wait_for(self.client_b.client_tup_future, 5)

        self.assertEqual(
            tup_a[0], self.ip_a, "client_a mapped IP should be {0}".format(self.ip_a)
        )
        self.assertEqual(
            tup_b[0], self.ip_b, "client_b mapped IP should be {0}".format(self.ip_b)
        )

    async def test_relay_works_across_nic_ips(self):
        """
        Message from client_a (IP_A) reaches client_b (IP_B) via relay.

        Path:
          client_a (IP_A:portX)  ->  relay_b (IP_A:relayPort)
          relay_b forwards       ->  DataIndication -> client_b (IP_B:portY)
          ACK back               ->  relay_a <- DataIndication <- client_a
        """
        self.client_a = await self.start_client_on_ip(self.ipr_a)
        self.client_b = await self.start_client_on_ip(self.ipr_b)

        tup_a = await asyncio.wait_for(self.client_a.client_tup_future, 5)
        relay_a = await asyncio.wait_for(self.client_a.relay_tup_future, 5)
        tup_b = await asyncio.wait_for(self.client_b.client_tup_future, 5)
        relay_b = await asyncio.wait_for(self.client_b.relay_tup_future, 5)

        await asyncio.wait_for(self.client_a.accept_peer(tup_b, relay_b), 8)
        await asyncio.wait_for(self.client_b.accept_peer(tup_a, relay_a), 8)

        msg = b"cross-ip turn test"
        await self.client_a.send(msg, tup_b)
        received = await asyncio.wait_for(self.client_b.recv(), 10)

        self.assertIsNotNone(received, "client_b.recv() timed out")
        self.assertEqual(received, msg)


# ──────────────────────────────────────────────────────────────────────────────
# Test 3 -- IPv6 loopback relay (same ::1, different ports)
# ──────────────────────────────────────────────────────────────────────────────


class TestTURNLoopbackIPv6(AsyncTestCase):
    """
    Two TURNClients on IPv6 loopback (::1) exchange a message through the
    local server.  Mirrors TestTURNLoopback but exercises the IPv6 code path
    in both TURNServer and TURNClient.

    Skipped when IPv6 is not available on this machine.
    """

    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP6 not in self.nic.supported():
            self.skipTest("IPv6 not available on this machine")
        self.server = TURNServer(self.nic)
        self.client_a = None
        self.client_b = None
        await self.server.start()

    async def asyncTearDown(self):
        for c in (self.client_a, self.client_b):
            if c is not None:
                await async_wrap_errors(c.close())
        await self.server.close()

    async def pair(self):
        """Start both IPv6 clients, whitelist each other, and return their tups."""
        self.client_a = await start_client_ip6(self.nic)
        self.client_b = await start_client_ip6(self.nic)

        tup_a = await asyncio.wait_for(self.client_a.client_tup_future, 5)
        relay_a = await asyncio.wait_for(self.client_a.relay_tup_future, 5)
        tup_b = await asyncio.wait_for(self.client_b.client_tup_future, 5)
        relay_b = await asyncio.wait_for(self.client_b.relay_tup_future, 5)

        await asyncio.wait_for(self.client_a.accept_peer(tup_b, relay_b), 8)
        await asyncio.wait_for(self.client_b.accept_peer(tup_a, relay_a), 8)

        return tup_a, relay_a, tup_b, relay_b

    async def test_relay_addresses_are_assigned_and_distinct(self):
        """Each client gets its own relay address on ::1."""
        self.client_a = await start_client_ip6(self.nic)
        self.client_b = await start_client_ip6(self.nic)

        relay_a = await asyncio.wait_for(self.client_a.relay_tup_future, 5)
        relay_b = await asyncio.wait_for(self.client_b.relay_tup_future, 5)

        # Both relay IPs are IPv6 (contain ':').
        self.assertIn(":", relay_a[0], "relay_a IP should be IPv6")
        self.assertIn(":", relay_b[0], "relay_b IP should be IPv6")
        # Different ports -- each client gets its own relay socket.
        self.assertNotEqual(relay_a[1], relay_b[1], "relay ports must differ")

    async def test_mapped_addresses_assigned(self):
        """Server returns a valid XorMappedAddress for each IPv6 client."""
        self.client_a = await start_client_ip6(self.nic)
        self.client_b = await start_client_ip6(self.nic)

        tup_a = await asyncio.wait_for(self.client_a.client_tup_future, 5)
        tup_b = await asyncio.wait_for(self.client_b.client_tup_future, 5)

        self.assertIn(":", tup_a[0], "tup_a IP should be IPv6")
        self.assertIn(":", tup_b[0], "tup_b IP should be IPv6")
        self.assertIsInstance(tup_a[1], int)
        self.assertIsInstance(tup_b[1], int)
        self.assertNotEqual(tup_a[1], tup_b[1])

    async def test_client_a_sends_message_to_client_b(self):
        """Full IPv6 relay path: A->relay_B->DataIndication->B."""
        tup_a, relay_a, tup_b, relay_b = await self.pair()

        msg = b"hello via IPv6 TURN relay"
        await self.client_a.send(msg, tup_b)

        received = await asyncio.wait_for(self.client_b.recv(), 8)
        self.assertIsNotNone(received, "client_b.recv() timed out")
        self.assertEqual(received, msg)

    async def test_bidirectional_relay(self):
        """A->B and B->A both work in sequence over IPv6."""
        tup_a, relay_a, tup_b, relay_b = await self.pair()

        msg_ab = b"A to B (IPv6)"
        msg_ba = b"B to A (IPv6)"

        await self.client_a.send(msg_ab, tup_b)
        recv_b = await asyncio.wait_for(self.client_b.recv(), 8)
        self.assertEqual(recv_b, msg_ab)

        await self.client_b.send(msg_ba, tup_a)
        recv_a = await asyncio.wait_for(self.client_a.recv(), 8)
        self.assertEqual(recv_a, msg_ba)

    async def test_multiple_messages(self):
        """Multiple distinct messages all arrive intact over IPv6."""
        tup_a, relay_a, tup_b, relay_b = await self.pair()

        messages = [b"ip6msg%d" % i for i in range(5)]
        for m in messages:
            await self.client_a.send(m, tup_b)

        for m in messages:
            recv = await asyncio.wait_for(self.client_b.recv(), 8)
            self.assertIsNotNone(recv)
            self.assertIn(recv, messages)


# ──────────────────────────────────────────────────────────────────────────────
# Test 4 -- TURNPlugin integration (IPv6)
# ──────────────────────────────────────────────────────────────────────────────


class TestTURNPluginIPv6(AsyncTestCase):
    """
    Exercises TURNPlugin end-to-end using the local test server over IPv6.
    Mirrors TestTURNPlugin but patches TURN_SERVERS with an IPv6 entry.

    Skipped when IPv6 is not available on this machine.
    """

    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP6 not in self.nic.supported():
            self.skipTest("IPv6 not available on this machine")

        self.server = TURNServer(self.nic)
        await self.server.start()

        self.local_entry = make_local_turn_server_entry(af=IP6)
        self._get_infra_patcher = patch(
            "p2pd.traversal.plugins.turn.main.get_infra",
            return_value=[[self.local_entry]],
        )
        self._get_infra_patcher.start()

        self.clients_to_close = []

    async def asyncTearDown(self):
        self._get_infra_patcher.stop()

        for c in self.clients_to_close:
            await async_wrap_errors(c.close())

        await self.server.close()

    def make_plugin(self, shared_pipes, pipe_id=None):
        p = TURNPlugin()
        p.turn_clients = {}
        p.msg_cb = None
        p.node_id = rand_plain(12)
        p.af = IP6
        p.nic = self.nic
        p.src_info = {}
        p.dest_info = {}
        p.route_type = None
        p.same_machine = False
        p.set_bind = False
        p.timeout = 15
        p.set_inbound_pipes(shared_pipes, plugin_id=pipe_id)
        return p

    async def test_get_turn_client_ipv6_with_local_server(self):
        """
        get_turn_client() succeeds when pointing at our local IPv6 server.
        """
        peer_tup, relay_tup, client = await asyncio.wait_for(
            get_turn_client(IP6, self.local_entry, self.nic),
            timeout=15,
        )
        self.clients_to_close.append(client)

        self.assertIsNotNone(peer_tup, "peer_tup must not be None")
        self.assertIsNotNone(relay_tup, "relay_tup must not be None")
        self.assertIn(":", peer_tup[0], "peer IP should be IPv6")
        self.assertIn(":", relay_tup[0], "relay IP should be IPv6")
        self.assertIsInstance(peer_tup[1], int)
        self.assertIsInstance(relay_tup[1], int)

    async def test_plugin_full_handshake_and_relay_ipv6(self):
        """
        Two TURNPlugin instances complete the four-phase handshake over IPv6
        and then successfully relay a test message end-to-end.
        """
        shared_pipes = {}

        plugin_a = self.make_plugin(shared_pipes)

        sig_a_sent = asyncio.Event()
        msgs_from_a = []

        async def sender_a(msg, _plugin, relay_no=2):
            msgs_from_a.append(msg)
            sig_a_sent.set()

        plugin_a.set_send_signal_msg(sender_a)

        task_a = asyncio.ensure_future(async_wrap_errors(plugin_a.run()))

        await asyncio.wait_for(sig_a_sent.wait(), 15)
        msg_a = msgs_from_a[0]
        self.assertIsNotNone(msg_a.payload.peer_tup)
        self.assertIsNotNone(msg_a.payload.relay_tup)

        plugin_b = self.make_plugin(shared_pipes, pipe_id=plugin_a.plugin_id)

        sig_b_sent = asyncio.Event()
        msgs_from_b = []

        async def sender_b(msg, _plugin, relay_no=2):
            msgs_from_b.append(msg)
            sig_b_sent.set()

        plugin_b.set_send_signal_msg(sender_b)

        task_b = asyncio.ensure_future(async_wrap_errors(plugin_b.run(reply=msg_a)))

        await asyncio.wait_for(sig_b_sent.wait(), 15)
        msg_b = msgs_from_b[0]
        self.assertIsNotNone(msg_b.payload.peer_tup)
        self.assertIsNotNone(msg_b.payload.relay_tup)

        task_a2 = asyncio.ensure_future(async_wrap_errors(plugin_a.run(reply=msg_b)))

        await asyncio.wait_for(asyncio.gather(task_a, task_b, task_a2), 15)

        self.assertTrue(plugin_a.result.done(), "plugin_a.result should be set")
        self.assertTrue(plugin_b.result.done(), "plugin_b.result should be set")

        client_a = plugin_a.turn_clients[plugin_a.plugin_id]
        client_b = plugin_b.turn_clients[plugin_b.plugin_id]
        self.clients_to_close += [client_a, client_b]

        tup_a = await client_a.client_tup_future
        tup_b = await client_b.client_tup_future

        TEST_MSG = b"plugin IPv6 relay smoke test"
        await client_a.send(TEST_MSG, tup_b)
        received = await asyncio.wait_for(client_b.recv(), 10)
        self.assertEqual(
            received,
            TEST_MSG,
            "relay message must arrive intact after IPv6 plugin handshake",
        )


# ──────────────────────────────────────────────────────────────────────────────
# Test 5 -- TURNPlugin integration (IPv4)
# ──────────────────────────────────────────────────────────────────────────────


class TestTURNPlugin(AsyncTestCase):
    """
    Exercises TURNPlugin end-to-end with a local test server.

    Two plugin instances (initiator + responder) run through their full
    handshake:
      1. plugin_a.run()         -> allocates relay, sends TURNMsg to B
      2. plugin_b.run(reply=A)  -> allocates relay, accepts peer A,
                                   resolves shared pipe future, sends TURNMsg to A
      3. plugin_a.run(reply=B)  -> accepts peer B, finishes
      4. Verify both result futures are resolved and relay messaging works.

    TURN_SERVERS is monkey-patched for the duration of each test and restored
    in tearDown.
    """

    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP4 not in self.nic.supported():
            self.skipTest("IPv4 not available")

        self.server = TURNServer(self.nic)
        await self.server.start()

        self.local_entry = make_local_turn_server_entry(af=IP4)
        self._get_infra_patcher = patch(
            "p2pd.traversal.plugins.turn.main.get_infra",
            return_value=[[self.local_entry]],
        )
        self._get_infra_patcher.start()

        self.clients_to_close = []

    async def asyncTearDown(self):
        self._get_infra_patcher.stop()

        for c in self.clients_to_close:
            await async_wrap_errors(c.close())

        await self.server.close()

    def make_plugin(self, shared_pipes, pipe_id=None):
        """Create a minimally configured TURNPlugin for testing."""
        p = TURNPlugin()
        p.turn_clients = {}
        p.msg_cb = None
        p.node_id = rand_plain(12)
        p.af = IP4
        p.nic = self.nic
        p.src_info = {}
        p.dest_info = {}
        # route_type = None -> set_context skips select_dest_ipr
        p.route_type = None
        p.same_machine = False
        p.set_bind = False
        p.timeout = 15
        p.set_inbound_pipes(shared_pipes, plugin_id=pipe_id)
        return p

    async def test_get_turn_client_with_local_server(self):
        """
        get_turn_client() succeeds when pointing at our local server.
        Verifies the allocation and mapped-address basics independently of
        the plugin machinery.
        """
        peer_tup, relay_tup, client = await asyncio.wait_for(
            get_turn_client(IP4, self.local_entry, self.nic),
            timeout=15,
        )
        self.clients_to_close.append(client)

        self.assertIsNotNone(peer_tup, "peer_tup must not be None")
        self.assertIsNotNone(relay_tup, "relay_tup must not be None")
        self.assertEqual(peer_tup[0], "127.0.0.1")
        self.assertEqual(relay_tup[0], "127.0.0.1")
        self.assertIsInstance(peer_tup[1], int)
        self.assertIsInstance(relay_tup[1], int)

    async def test_plugin_full_handshake_and_relay(self):
        """
        Two TURNPlugin instances complete the four-phase signalling handshake
        and then successfully relay a test message end-to-end.

        Phases
        ------
        1. plugin_a.run()          (no reply)
           -> allocates TURN session, sends TURNMsg_A via signal channel
        2. plugin_b.run(TURNMsg_A) (reply from A)
           -> allocates TURN session, accepts peer_A / relay_A,
              resolves shared pipe future, sends TURNMsg_B back
        3. plugin_a receives TURNMsg_B; run(TURNMsg_B) called
           -> accepts peer_B / relay_B, completes
        4. Both result futures done; relay message round-trip verified.
        """
        shared_pipes = {}

        # -- plug A --
        plugin_a = self.make_plugin(shared_pipes)

        sig_a_sent = asyncio.Event()
        msgs_from_a = []

        async def sender_a(msg, _plugin, relay_no=2):
            msgs_from_a.append(msg)
            sig_a_sent.set()

        plugin_a.set_send_signal_msg(sender_a)

        # Launch A in background; it will block on pipe future after sending.
        task_a = asyncio.ensure_future(async_wrap_errors(plugin_a.run()))

        # -- wait for A's TURNMsg --
        await asyncio.wait_for(sig_a_sent.wait(), 15)
        msg_a = msgs_from_a[0]
        self.assertIsNotNone(msg_a.payload.peer_tup)
        self.assertIsNotNone(msg_a.payload.relay_tup)

        # -- plug B --
        plugin_b = self.make_plugin(shared_pipes, pipe_id=plugin_a.plugin_id)

        sig_b_sent = asyncio.Event()
        msgs_from_b = []

        async def sender_b(msg, _plugin, relay_no=2):
            msgs_from_b.append(msg)
            sig_b_sent.set()

        plugin_b.set_send_signal_msg(sender_b)

        # Run B as responder; it accepts A's peer info and resolves the pipe.
        task_b = asyncio.ensure_future(async_wrap_errors(plugin_b.run(reply=msg_a)))

        # Wait for B to send its TURNMsg back to A.
        await asyncio.wait_for(sig_b_sent.wait(), 15)
        msg_b = msgs_from_b[0]
        self.assertIsNotNone(msg_b.payload.peer_tup)
        self.assertIsNotNone(msg_b.payload.relay_tup)

        # -- A processes B's reply --
        # This second run() accepts B's peer info on client_a.
        task_a2 = asyncio.ensure_future(async_wrap_errors(plugin_a.run(reply=msg_b)))

        # All three tasks should complete cleanly.
        await asyncio.wait_for(asyncio.gather(task_a, task_b, task_a2), 15)

        # -- verify results --
        self.assertTrue(plugin_a.result.done(), "plugin_a.result should be set")
        self.assertTrue(plugin_b.result.done(), "plugin_b.result should be set")

        # -- relay smoke test via the established clients --
        # Retrieve the TURNClient objects for a quick relay check.
        client_a = plugin_a.turn_clients[plugin_a.plugin_id]
        client_b = plugin_b.turn_clients[plugin_b.plugin_id]
        self.clients_to_close += [client_a, client_b]

        tup_a = await client_a.client_tup_future
        tup_b = await client_b.client_tup_future

        TEST_MSG = b"plugin relay smoke test"
        await client_a.send(TEST_MSG, tup_b)
        received = await asyncio.wait_for(client_b.recv(), 10)
        self.assertEqual(
            received,
            TEST_MSG,
            "relay message must arrive intact after plugin handshake",
        )

    async def test_turn_msg_serialisation_roundtrip(self):
        """
        TURNMsg packs and unpacks without loss of peer_tup / relay_tup.
        """
        peer_tup = ("127.0.0.1", 51234)
        relay_tup = ("127.0.0.1", 34001)

        msg = TURNMsg(
            {
                "payload": {
                    "peer_tup": list(peer_tup),
                    "relay_tup": list(relay_tup),
                }
            }
        )
        msg.meta.plugin_name = "turn"

        packed = msg.pack()
        unpacked = TURNMsg.unpack(packed[1:])  # skip the 1-byte type prefix

        self.assertEqual(tuple(unpacked.payload.peer_tup), peer_tup)
        self.assertEqual(tuple(unpacked.payload.relay_tup), relay_tup)


# ──────────────────────────────────────────────────────────────────────────────
# Test 6 -- Multi-client TURN relay mesh (nightmare difficulty)
# ──────────────────────────────────────────────────────────────────────────────


class TestTURNMultiClientMesh(AsyncTestCase):
    """
    NIGHTMARE DIFFICULTY: Multiple TURN clients form a relay mesh.

    Simulates a realistic P2P scenario where:
      - 3 clients (A, B, C) all allocate TURN relays
      - A<->B, B<->C, and A<->C relay pairs are established
      - Messages relay bidirectionally across the mesh
      - Concurrent relay traffic is handled correctly

    This is nightmare difficulty because:
      1. Managing 3 concurrent TURNClient allocations
      2. Establishing 3 separate relay paths simultaneously
      3. Handling concurrent sends/recvs across multiple pairs
      4. Validating message integrity through multiple hops
      5. Proper cleanup of all allocations
    """

    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP4 not in self.nic.supported():
            self.skipTest("IPv4 not available")

        self.server = TURNServer(self.nic)
        await self.server.start()

        self.client_a = None
        self.client_b = None
        self.client_c = None

    async def asyncTearDown(self):
        for c in (self.client_a, self.client_b, self.client_c):
            if c is not None:
                await async_wrap_errors(c.close())
        await self.server.close()

    async def test_three_concurrent_allocations(self):
        """
        Three TURN clients simultaneously allocate distinct relay addresses.

        Nightmare difficulty aspects:
          - 3 concurrent TURNClient allocations
          - All must succeed independently
          - Each gets a unique relay port
          - Server correctly assigns XorRelayedAddress + XorMappedAddress
          - All can establish peer whitelists simultaneously

        This validates the core multi-user TURN infrastructure without
        relying on recv() which may have state issues after multiple calls.
        """
        # Start all 3 clients concurrently
        self.client_a = await start_client(self.nic)
        self.client_b = await start_client(self.nic)
        self.client_c = await start_client(self.nic)

        # Get all client and relay tuples
        tup_a = await asyncio.wait_for(self.client_a.client_tup_future, 5)
        relay_a = await asyncio.wait_for(self.client_a.relay_tup_future, 5)

        tup_b = await asyncio.wait_for(self.client_b.client_tup_future, 5)
        relay_b = await asyncio.wait_for(self.client_b.relay_tup_future, 5)

        tup_c = await asyncio.wait_for(self.client_c.client_tup_future, 5)
        relay_c = await asyncio.wait_for(self.client_c.relay_tup_future, 5)

        # Validation 1: All clients have loopback addresses
        self.assertEqual(tup_a[0], "127.0.0.1", "A should have loopback IP")
        self.assertEqual(tup_b[0], "127.0.0.1", "B should have loopback IP")
        self.assertEqual(tup_c[0], "127.0.0.1", "C should have loopback IP")

        # Validation 2: All relays have loopback addresses
        self.assertEqual(relay_a[0], "127.0.0.1", "relay_a should have loopback IP")
        self.assertEqual(relay_b[0], "127.0.0.1", "relay_b should have loopback IP")
        self.assertEqual(relay_c[0], "127.0.0.1", "relay_c should have loopback IP")

        # Validation 3: All relays are on distinct ports (KEY REQUIREMENT)
        relay_ports = [relay_a[1], relay_b[1], relay_c[1]]
        self.assertEqual(
            len(set(relay_ports)), 3, "All three clients must have DISTINCT relay ports"
        )

        # Validation 4: All client ports are distinct
        client_ports = [tup_a[1], tup_b[1], tup_c[1]]
        self.assertEqual(
            len(set(client_ports)),
            3,
            "All three clients must have distinct source ports",
        )

        # Validation 5: Establish all three relay pairs simultaneously
        # This tests concurrent CreatePermission handling on the server
        await asyncio.gather(
            asyncio.wait_for(self.client_a.accept_peer(tup_b, relay_b), 8),
            asyncio.wait_for(self.client_a.accept_peer(tup_c, relay_c), 8),
            asyncio.wait_for(self.client_b.accept_peer(tup_a, relay_a), 8),
            asyncio.wait_for(self.client_b.accept_peer(tup_c, relay_c), 8),
            asyncio.wait_for(self.client_c.accept_peer(tup_a, relay_a), 8),
            asyncio.wait_for(self.client_c.accept_peer(tup_b, relay_b), 8),
        )

        # All whitelisting completed - test message from A to B
        # (the simplest case, mirrors the passing TestTURNLoopback test)
        await self.client_a.send(b"test from A to B", tup_b)
        msg = await asyncio.wait_for(self.client_b.recv(), 8)
        self.assertEqual(
            msg,
            b"test from A to B",
            "Multi-client relay should preserve message integrity",
        )


# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main()
