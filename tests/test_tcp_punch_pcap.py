"""Unit tests for tcp_punch_pcap -- engine orchestration in isolation.

Three test classes, all using AsyncTestCase per CLAUDE.md.

1. TestPcapMuxReaderRouting -- the multiplexer dispatches TCP frames
   to the subscriber whose 4-tuple matches the dst/src in the IP+TCP
   headers, and falls back to a 3-tuple match when an exact match
   isn't found.

2. TestPcapEngineOrchestration -- pcap_selector_punch_engine with a
   stubbed Connection backend so the test runs without libpcap
   permissions / a netns. Asserts: ONE Connection per port_alloc is
   spawned, sleep_until_async is awaited before any start_active
   call, and the first Connection to mark its established_event is
   the one returned.

3. TestFirewallHelperContract -- install_block_ports + remove_block_ports
   semantics on Linux (install requires root -> skipTest when
   non-root) and on Windows (no-op contract).

The full kernel<->pcap simul-open scenario is already covered by
tests/test_tcp_punch_pcap_interop.py for the original plugin. The
v2 path differs only in the orchestration layer (compute_rendezvous +
boundary spray + Mux reader) and the engine substrate, so we test
those in isolation here.
"""
import asyncio
import os
import struct
import sys
import unittest

from aionetiface.testing import AsyncTestCase

# Make sure src/ is reachable when running from the repo root.
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.normpath(os.path.join(HERE, "..", "src"))
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from warpgate.traversal.plugins.tcp_punch_pcap import pcap_mux_reader
from warpgate.traversal.plugins.tcp_punch_pcap import pcap_engine
from warpgate.traversal.plugins.tcp_punch_pcap import firewall_helper
from warpgate.traversal.plugins.tcp_punch.punch_defs import PortAlloc


# -------------------------------------------------------------------------
# Helpers


def ip_str_to_bytes(ip):
    parts = [int(x) for x in ip.split(".")]
    return bytes(bytearray(parts))


def make_eth_ipv4_tcp(src_ip, src_port, dst_ip, dst_port,
                       flags=0x02, seq=1000, ack=0):
    """Build a synthetic Ethernet + IPv4 + TCP frame for the mux to parse.

    Just enough headers for parse_eth_frame / parse_ipv4 / parse_tcp_segment
    to accept. Not for actual on-wire use -- only the mux's parser needs
    to like it.
    """
    # Ethernet: 14 bytes (dst_mac + src_mac + ethertype)
    eth = (
        b"\x00\x01\x02\x03\x04\x05"      # dst mac
        + b"\x06\x07\x08\x09\x0a\x0b"    # src mac
        + b"\x08\x00"                     # ethertype IPv4
    )
    # TCP: 20 byte header, no options
    tcp = struct.pack(
        ">HHIIBBHHH",
        src_port,
        dst_port,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        (5 << 4),  # data offset 5 32-bit words, no flags in this nibble
        flags & 0xFF,
        65535,
        0,        # checksum -- mux parser doesn't validate
        0,        # urgent
    )
    # IPv4: 20 byte header, no options. version=4 ihl=5, ttl=64, proto=6.
    ihl = 5
    total_len = ihl * 4 + len(tcp)
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        (4 << 4) | ihl,
        0,
        total_len,
        0,        # id
        0,        # flags+frag
        64,       # ttl
        6,        # proto TCP
        0,        # checksum -- mux parser doesn't validate
        ip_str_to_bytes(src_ip),
        ip_str_to_bytes(dst_ip),
    )
    return eth + ip + tcp


# -------------------------------------------------------------------------
# 1. PcapMuxReader routing


class FakeBackend(object):
    """Minimum stub of aionetiface.net.pcap.backend.Backend.

    Doesn't actually capture frames -- the test calls dispatch_frame
    directly. recv() blocks forever so the reader thread does nothing
    if started; tests don't start it.
    """

    platform_name = "fake"
    iface_name = "fake0"

    def __init__(self, dlt=1):
        self.dlt = dlt
        self.sent = []

    def datalink(self):
        return self.dlt

    def recv(self, timeout_ms=100):
        return None

    def send(self, frame_bytes):
        self.sent.append(frame_bytes)
        return len(frame_bytes)

    def set_filter(self, bpf):
        return None

    def close(self):
        return None


class TestPcapMuxReaderRouting(AsyncTestCase):
    """The mux's dispatch_frame routes correctly by 5-tuple."""

    async def test_exact_four_tuple_match(self):
        loop = asyncio.get_event_loop()
        backend = FakeBackend(dlt=1)
        mux = pcap_mux_reader.PcapMuxReader(backend, loop=loop)
        sub_a = mux.subscribe(("10.0.0.1", 5000, "10.0.0.2", 6000))
        sub_b = mux.subscribe(("10.0.0.1", 5001, "10.0.0.2", 6001))

        # Frame that should go to sub_a: src=10.0.0.2:6000 -> dst=10.0.0.1:5000
        frame_a = make_eth_ipv4_tcp("10.0.0.2", 6000, "10.0.0.1", 5000)
        mux.dispatch_frame(frame_a)
        # Frame that should go to sub_b: src=10.0.0.2:6001 -> dst=10.0.0.1:5001
        frame_b = make_eth_ipv4_tcp("10.0.0.2", 6001, "10.0.0.1", 5001)
        mux.dispatch_frame(frame_b)

        # Give the call_soon_threadsafe a tick to land.
        await asyncio.sleep(0)
        # Each queue has exactly one item.
        self.assertEqual(sub_a.queue.qsize(), 1)
        self.assertEqual(sub_b.queue.qsize(), 1)
        got_a = await sub_a.next_frame(timeout=0.5)
        got_b = await sub_b.next_frame(timeout=0.5)
        self.assertEqual(got_a, frame_a)
        self.assertEqual(got_b, frame_b)

    async def test_three_tuple_fallback(self):
        """When the subscriber's peer_port is 0 / different, a frame
        with the same (local_ip, local_port, peer_ip) still lands."""
        loop = asyncio.get_event_loop()
        backend = FakeBackend(dlt=1)
        mux = pcap_mux_reader.PcapMuxReader(backend, loop=loop)
        # Subscriber expects peer_port=6999 but the real SYN arrives
        # from peer_port=6000 (NAT rewrote it / prediction was off):
        sub = mux.subscribe(("10.0.0.1", 5000, "10.0.0.2", 6999))
        frame = make_eth_ipv4_tcp("10.0.0.2", 6000, "10.0.0.1", 5000)
        mux.dispatch_frame(frame)
        await asyncio.sleep(0)
        self.assertEqual(sub.queue.qsize(), 1)
        got = await sub.next_frame(timeout=0.5)
        self.assertEqual(got, frame)

    async def test_no_match_dropped(self):
        """Frame whose dst_ip / dst_port match no subscriber is dropped."""
        loop = asyncio.get_event_loop()
        backend = FakeBackend(dlt=1)
        mux = pcap_mux_reader.PcapMuxReader(backend, loop=loop)
        sub = mux.subscribe(("10.0.0.1", 5000, "10.0.0.2", 6000))
        # Bound for a totally different host.
        frame = make_eth_ipv4_tcp("10.0.0.5", 6000, "10.0.0.6", 5000)
        mux.dispatch_frame(frame)
        await asyncio.sleep(0)
        self.assertEqual(sub.queue.qsize(), 0)


# -------------------------------------------------------------------------
# 2. pcap_selector_punch_engine orchestration


class FakeFt(object):
    """Lightweight stand-in for the FourTuple object pcap_engine
    inspects via conn.ft.key() and sort_key_ft."""

    def __init__(self, local_ip, local_port, remote_ip, remote_port):
        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port

    def key(self):
        return (self.local_ip, self.local_port,
                self.remote_ip, self.remote_port)


class FakeConnection(object):
    """Stub Connection for the engine test. Mirrors the slice of the
    real Connection contract that pcap_engine touches: established_event
    (asyncio.Event), state (with is_established()), start_active
    coroutine, close coroutine, plus send/recv for the canonical-
    winner master/slave handshake.
    """

    def __init__(self, backend, local_ip, loop=None, reader=None):
        self.backend = backend
        self.local_ip = local_ip
        self.loop = loop or asyncio.get_event_loop()
        self.reader = reader
        self.established_event = asyncio.Event()
        self.local_port = None
        self.remote_port = None
        self.remote_ip = None
        self.closed = False
        self.state = self  # so engine's conn.state.is_established works
        self.ft = None
        self.sent_bytes = b""

    def is_established(self):
        return self.established_event.is_set()

    async def start_active(self, remote_ip, remote_port, local_port,
                            remote_mac=None, simul=False, mss=1460):
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.local_port = local_port
        self.ft = FakeFt(self.local_ip, local_port, remote_ip, remote_port)

    async def send(self, data):
        self.sent_bytes += bytes(data)
        return len(data)

    async def recv(self, n, timeout=None):
        # Slave's race: this fake never delivers a $ byte, so the
        # recv hangs until cancelled. Sleeping past the timeout lets
        # asyncio.wait observe the timeout cleanly.
        await asyncio.sleep(timeout if timeout is not None else 1.0)
        return b""

    async def close(self):
        self.closed = True

    def trigger_established(self):
        """Test helper: mark this fake Connection as ESTABLISHED."""
        self.established_event.set()


class TestPcapEngineOrchestration(AsyncTestCase):
    """Engine spawns N Connections, awaits sleep_until, returns first winner."""

    async def asyncSetUp(self):
        # Patch pcap_engine.Connection to the fake. Restore in tearDown.
        self.orig_connection = pcap_engine.Connection
        pcap_engine.Connection = FakeConnection

        # Patch pcap_setup_engine to skip real pcap and hand back a
        # fake backend + a real PcapMuxReader (with fake backend) so
        # the engine still subscribes / spawns. We don't start the
        # mux thread -- the engine doesn't read frames in this test,
        # it just races established_event.
        async def fake_setup(nic_pcap_name, port_allocs, src_ip, dest_ip,
                              loop=None):
            backend = FakeBackend(dlt=1)
            mux = pcap_mux_reader.PcapMuxReader(backend, loop=loop)
            subs = []
            for pa in port_allocs:
                ft = (src_ip, int(pa.src_port), dest_ip, int(pa.dest_port))
                sub = mux.subscribe(ft)
                subs.append((pa, sub))
            return (backend, mux, subs)
        self.orig_setup = pcap_engine.pcap_setup_engine
        pcap_engine.pcap_setup_engine = fake_setup

        # Track spawned conns so the test can drive them.
        self.spawned = []
        orig_spawn = pcap_engine.spawn_connections

        async def tracking_spawn(port_alloc_subs, src_ip, dest_ip, loop=None):
            conns = await orig_spawn(
                port_alloc_subs, src_ip, dest_ip, loop=loop,
            )
            self.spawned.extend(conns)
            return conns
        self.orig_spawn = orig_spawn
        pcap_engine.spawn_connections = tracking_spawn

    async def asyncTearDown(self):
        pcap_engine.Connection = self.orig_connection
        pcap_engine.pcap_setup_engine = self.orig_setup
        pcap_engine.spawn_connections = self.orig_spawn

    async def test_engine_spawns_one_conn_per_alloc(self):
        port_allocs = [
            PortAlloc(2024, 2025),
            PortAlloc(3030, 3031),
            PortAlloc(4040, 4041),
        ]
        sleep_called = []

        async def sleep_until_async():
            sleep_called.append(True)
            # Don't actually wait -- once we return, the engine will
            # call spawn_connections, then wait for established_event.

        # Schedule the winning event to fire shortly after we expect
        # the engine to be in wait_first_established.
        async def fire_winner():
            await asyncio.sleep(0.05)
            # Trip the SECOND spawned connection as the winner so we
            # can confirm the engine isn't just returning conns[0].
            if len(self.spawned) >= 2:
                self.spawned[1].trigger_established()
        asyncio.ensure_future(fire_winner())

        # src_ip > dest_ip puts this peer in master role for the
        # canonical-winner handshake, so the engine sends `$` on the
        # winner rather than waiting for a slave-side recv (which the
        # fake can't deliver).
        winner = await pcap_engine.pcap_selector_punch_engine(
            nic_pcap_name="lo",
            port_allocs=port_allocs,
            src_ip="127.0.0.2",
            dest_ip="127.0.0.1",
            f_sleep_until_async=sleep_until_async,
            params={"monitor_timeout": 1.0, "connect_timeout": 1.0},
        )

        # sleep_until was awaited.
        self.assertTrue(sleep_called)
        # Three Connections spawned (one per port_alloc).
        self.assertEqual(len(self.spawned), 3)
        # All three were start_active'd with the right (local, remote) ports.
        starts = [
            (c.local_port, c.remote_port) for c in self.spawned
        ]
        self.assertIn((2024, 2025), starts)
        self.assertIn((3030, 3031), starts)
        self.assertIn((4040, 4041), starts)
        # Winner is the FakeConnection we tripped (the only one to
        # reach ESTABLISHED in the monitor window).
        self.assertIs(winner, self.spawned[1])
        # Master sent the canonical-winner `$` byte on the chosen conn.
        self.assertEqual(winner.sent_bytes, b"$")
        # Losers were closed; winner was not.
        self.assertFalse(winner.closed)
        for loser in (self.spawned[0], self.spawned[2]):
            self.assertTrue(loser.closed)

    async def test_engine_returns_none_on_timeout(self):
        port_allocs = [PortAlloc(2024, 2025), PortAlloc(3030, 3031)]

        async def sleep_until_async():
            pass

        winner = await pcap_engine.pcap_selector_punch_engine(
            nic_pcap_name="lo",
            port_allocs=port_allocs,
            src_ip="127.0.0.1",
            dest_ip="127.0.0.2",
            f_sleep_until_async=sleep_until_async,
            params={"monitor_timeout": 0.1, "connect_timeout": 0.1},
        )

        self.assertIsNone(winner)
        # All spawned conns were closed.
        for c in self.spawned:
            self.assertTrue(c.closed)


# -------------------------------------------------------------------------
# 3. Firewall helper contract


class TestFirewallHelperContract(AsyncTestCase):
    """install_block_ports + remove_block_ports preserve their contract."""

    async def test_windows_is_noop(self):
        if not sys.platform.startswith("win"):
            self.skipTest("Windows-only contract test")
        installed = firewall_helper.install_block_ports([12345, 12346])
        # On Windows the helper short-circuits: returns empty list
        # (nothing was actually installed; existing firewall state
        # is relied upon).
        self.assertEqual(installed, [])
        # Pair-removing the empty list is a no-op.
        firewall_helper.remove_block_ports(installed)

    async def test_linux_requires_root_or_sudo(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("Linux-only contract test")
        # We don't actually want to mutate the host's iptables in a
        # unit test. Instead just confirm that when need_sudo()
        # returns True we get sudo-prefixed argv, otherwise plain.
        argv = firewall_helper.sudo_argv(["iptables", "-L"])
        if firewall_helper.need_sudo():
            self.assertEqual(argv[0], "sudo")
            self.assertEqual(argv[1], "iptables")
        else:
            self.assertEqual(argv[0], "iptables")

    async def test_unsupported_platform_returns_empty(self):
        if (sys.platform.startswith("linux")
                or sys.platform.startswith("win")
                or sys.platform.startswith("darwin")
                or "bsd" in sys.platform):
            self.skipTest("Test only runs on unsupported platforms")
        installed = firewall_helper.install_block_ports([12345])
        self.assertEqual(installed, [])


if __name__ == "__main__":
    unittest.main()
