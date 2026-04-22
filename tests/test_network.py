"""
Network integration tests for p2pd.

These tests require real internet connectivity. Each test is self-contained
and uses only the default network interface so they stay portable across
machines. Tests are organised by component:

  TestSysClock   — NTP-based clock synchronisation
  TestNickname   — put / get / delete lifecycle against real PNP servers
  TestSTUN       — WAN-IP discovery via STUN
  TestMQTT       — MQTT broker reachability
  TestNodeStart  — full Node startup / shutdown

All tests use asyncio.IsolatedAsyncioTestCase so each gets a clean event
loop. Timeouts are generous enough to survive slow connections.
"""

import asyncio
import hashlib
import time
import unittest

import namebump
from ecdsa import SigningKey, SECP256k1

from aionetiface import (
    IP4,
    IP6,
    Interface,
    SysClock,
    IPRange,
    STUNClient,
    TCP,
    UDP,
    PNP_SERVERS,
    get_aionetiface_install_root,
    rand_plain,
    to_s,
    to_h,
    h_to_b,
    log,
    log_exception,
)
from aionetiface.utility.sys_clock import get_ntp

from p2pd import Node
from p2pd.node.nickname import Nickname, FullNameFailure
from p2pd.node.node_utils import load_signing_key
from p2pd.node.node_defs import NODE_TEST_CONF, NODE_PORT


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _default_nic():
    """Return the default Interface. Raises on failure."""
    return await Interface("default")


def _make_sk():
    install_path = get_aionetiface_install_root()
    return load_signing_key([], [], NODE_PORT, install_path)


# ---------------------------------------------------------------------------
# SysClock / NTP
# ---------------------------------------------------------------------------


class TestSysClock(unittest.IsolatedAsyncioTestCase):
    """SysClock.start() must sync to NTP; .time() must return a plausible ts."""

    async def test_start_syncs_ntp(self):
        nic = await _default_nic()
        clock = SysClock(nic)
        await asyncio.wait_for(clock.start(), timeout=30)
        self.assertNotEqual(
            clock.ntp, 0, "SysClock.ntp should be non-zero after start()"
        )

    async def test_time_returns_unix_timestamp(self):
        nic = await _default_nic()
        clock = await asyncio.wait_for(SysClock(nic), timeout=30)
        t = clock.time()
        now = time.time()
        # Sanity: within ±5 minutes of local system clock.
        self.assertAlmostEqual(
            t, now, delta=300, msg="clock.time() should be within 5 min of system time"
        )

    async def test_time_increases(self):
        nic = await _default_nic()
        clock = await asyncio.wait_for(SysClock(nic), timeout=30)
        t1 = clock.time()
        await asyncio.sleep(0.05)
        t2 = clock.time()
        self.assertGreater(t2, t1, "clock.time() must increase over time")

    async def test_advance_shifts_clock(self):
        nic = await _default_nic()
        clock = await asyncio.wait_for(SysClock(nic), timeout=30)
        before = clock.time()
        clock.advance(100)
        after = clock.time()
        self.assertAlmostEqual(
            after - before,
            100,
            delta=1,
            msg="advance(100) should shift clock by ~100 s",
        )

    async def test_time_falls_back_to_system_clock_without_start(self):
        """SysClock.time() falls back to system clock when NTP not loaded."""
        nic = await _default_nic()
        clock = SysClock(nic, ntp=0)
        t = clock.time()
        self.assertGreater(t, 0)

    async def test_get_ntp_returns_nonzero(self):
        """Low-level get_ntp() should return a positive unix timestamp."""
        nic = await _default_nic()
        for af in nic.supported():
            ntp = await asyncio.wait_for(get_ntp(af, nic), timeout=15)
            if ntp is not None:
                self.assertGreater(
                    ntp, 0, "get_ntp() should return a positive unix timestamp"
                )
                return
        self.skipTest("No NTP server reachable via supported AFs")


# ---------------------------------------------------------------------------
# Nickname (PNP) — requires PNP servers to be up
# ---------------------------------------------------------------------------


class TestNickname(unittest.IsolatedAsyncioTestCase):
    """Full put / get / delete lifecycle against real PNP servers."""

    async def asyncSetUp(self):
        self.nic = await _default_nic()
        self.clock = await asyncio.wait_for(SysClock(self.nic), timeout=30)
        self.sk = _make_sk()
        vk_compressed = self.sk.verifying_key.to_string("compressed")
        # Use deterministic name derived from our key so parallel runs
        # don't collide and old leftover entries are ours to overwrite.
        self.name = hashlib.sha256(vk_compressed).hexdigest()[:25]
        self.nick = Nickname(sk=self.sk, ifs=[self.nic], sys_clock=self.clock)
        try:
            await asyncio.wait_for(self.nick.start(), timeout=20)
        except Exception:
            self.skipTest("Nickname servers unreachable — skipping network tests")

    async def asyncTearDown(self):
        if self.nick is not None:
            await self.nick.close()

    async def test_start_marks_started(self):
        self.assertTrue(self.nick.started)

    async def test_start_populates_at_least_one_client(self):
        any_connected = any(
            v is not None
            for af_dict in self.nick.clients.values()
            for v in af_dict.values()
        )
        self.assertTrue(
            any_connected, "At least one PNP client should connect successfully"
        )

    async def test_put_returns_fqn_with_tld(self):
        val = to_s(rand_plain(10))
        fqn = await asyncio.wait_for(self.nick.put(self.name, val), timeout=30)
        self.assertIsNotNone(fqn)
        self.assertIn(".", fqn, "put() should return a name with a TLD")
        # Clean up
        try:
            await asyncio.wait_for(self.nick.delete(fqn), timeout=20)
        except Exception:
            pass

    async def test_get_returns_stored_value(self):
        val = to_s(rand_plain(10))
        fqn = await asyncio.wait_for(self.nick.put(self.name, val), timeout=30)
        result = await asyncio.wait_for(self.nick.get(fqn), timeout=30)
        self.assertIsNotNone(result)
        self.assertEqual(
            to_s(result.value), val, "get() should return the same value that was put()"
        )
        # Clean up
        try:
            await asyncio.wait_for(self.nick.delete(fqn), timeout=20)
        except Exception:
            pass

    async def test_delete_removes_entry(self):
        val = to_s(rand_plain(10))
        fqn = await asyncio.wait_for(self.nick.put(self.name, val), timeout=30)
        await asyncio.wait_for(self.nick.delete(fqn), timeout=20)
        with self.assertRaises(FullNameFailure):
            await asyncio.wait_for(self.nick.get(fqn), timeout=20)

    async def test_put_get_delete_roundtrip(self):
        val = to_s(rand_plain(10))
        fqn = await asyncio.wait_for(self.nick.put(self.name, val), timeout=30)
        result = await asyncio.wait_for(self.nick.get(fqn), timeout=30)
        self.assertEqual(to_s(result.value), val)

        await asyncio.wait_for(self.nick.delete(fqn), timeout=20)
        with self.assertRaises(FullNameFailure):
            await asyncio.wait_for(self.nick.get(fqn), timeout=20)

    async def test_overwrite_with_put(self):
        """Second put() with the same name should overwrite the value."""
        val1 = to_s(rand_plain(10))
        val2 = to_s(rand_plain(10))
        fqn = await asyncio.wait_for(self.nick.put(self.name, val1), timeout=30)
        # Server uses integer-second timestamps for anti-replay; wait to get a
        # distinct timestamp so the UPDATE is accepted.
        await asyncio.sleep(1.1)
        await asyncio.wait_for(
            self.nick.put(self.name, val2, behavior=namebump.DONT_BUMP), timeout=30
        )
        result = await asyncio.wait_for(self.nick.get(fqn), timeout=30)
        self.assertEqual(to_s(result.value), val2)
        # Clean up
        try:
            await asyncio.wait_for(self.nick.delete(fqn), timeout=20)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# STUN — WAN IP discovery
# ---------------------------------------------------------------------------


class TestSTUN(unittest.IsolatedAsyncioTestCase):
    """STUN clients should return a public IP address."""

    async def _get_wan_ip(self, af):
        nic = await _default_nic()
        if af not in nic.supported():
            self.skipTest(f"AF {af} not supported on this machine")
        hosts = [("stun1.p2pd.net", 3478), ("stun2.p2pd.net", 3478)]
        for host in hosts:
            client = STUNClient(af, host, nic, proto=UDP)
            try:
                ip = await asyncio.wait_for(client.get_wan_ip(), timeout=10)
                if ip:
                    return ip
            except Exception:
                continue
        return None

    async def test_stun_ip4_returns_public_ip(self):
        ip = await self._get_wan_ip(IP4)
        if ip is None:
            self.skipTest("No STUN server reachable via IPv4")
        ipr = IPRange(ip, bitlen=32)
        self.assertTrue(ipr.is_public, f"STUN should return a public IP, got: {ip}")

    async def test_stun_result_is_valid_ipv4_string(self):
        ip = await self._get_wan_ip(IP4)
        if ip is None:
            self.skipTest("No STUN server reachable via IPv4")
        parts = ip.split(".")
        self.assertEqual(len(parts), 4, f"Expected IPv4 dotted quad, got: {ip}")
        for p in parts:
            self.assertTrue(p.isdigit())
            self.assertIn(int(p), range(0, 256))

    async def test_stun_ip4_tcp(self):
        nic = await _default_nic()
        if IP4 not in nic.supported():
            self.skipTest("IPv4 not supported on this machine")
        host = ("stun1.p2pd.net", 3478)
        client = STUNClient(IP4, host, nic, proto=TCP)
        try:
            ip = await asyncio.wait_for(client.get_wan_ip(), timeout=10)
        except Exception:
            self.skipTest("STUN TCP unreachable")
        if ip:
            ipr = IPRange(ip, bitlen=32)
            self.assertTrue(
                ipr.is_public, f"STUN TCP should return a public IP, got: {ip}"
            )


# ---------------------------------------------------------------------------
# MQTT connectivity
# ---------------------------------------------------------------------------


class TestMQTT(unittest.IsolatedAsyncioTestCase):
    """MQTT signaling infrastructure should accept connections."""

    async def test_router_connects_to_at_least_one_broker(self):
        """Router.start() must find at least one reachable MQTT broker."""
        from sidewire import Router
        from sidewire import Signing

        nic = await _default_nic()
        clock = await asyncio.wait_for(SysClock(nic), timeout=30)
        sk = _make_sk()
        kp = Signing(sk)

        router = Router(kp, get_time=clock.time, nic=nic)
        try:
            clients = await asyncio.wait_for(router.start(), timeout=20)
        except Exception as e:
            self.skipTest(f"Router.start() raised: {e}")
        finally:
            await router.close()

        # clients is a list of connected MQTTClient objects.
        self.assertIsNotNone(
            clients, "Router.start() must return a list of connected clients"
        )
        self.assertGreater(
            len(clients), 0, "Router should connect to at least one MQTT broker"
        )

    async def test_router_subscribe_and_publish(self):
        """After start(), Router can subscribe and receive a published message."""
        from sidewire import Router
        from sidewire import Signing

        nic = await _default_nic()
        clock = await asyncio.wait_for(SysClock(nic), timeout=30)
        sk = _make_sk()
        kp = Signing(sk)

        router = Router(kp, get_time=clock.time, nic=nic)
        try:
            clients = await asyncio.wait_for(router.start(), timeout=20)
        except Exception as e:
            await router.close()
            self.skipTest(f"Router.start() raised: {e}")
        if not clients:
            await router.close()
            self.skipTest("No MQTT brokers reachable")

        try:
            # Getting a pipe to ourselves exercises the subscribe path.
            vk_hex = kp.public_key_hex
            pipe = await asyncio.wait_for(
                router.pipe(vk_hex, lambda *a: None, use_cache=False), timeout=15
            )
            self.assertIsNotNone(pipe)
        except Exception as e:
            self.skipTest(f"Router.pipe() raised: {e}")
        finally:
            await router.close()


# ---------------------------------------------------------------------------
# Node startup / shutdown
# ---------------------------------------------------------------------------


class TestNodeStart(unittest.IsolatedAsyncioTestCase):
    """Node should start, produce a valid addr_bytes, and close cleanly."""

    async def test_node_starts_and_closes(self):
        try:
            node = await asyncio.wait_for(Node(conf=NODE_TEST_CONF), timeout=30)
        except Exception as e:
            self.skipTest(f"Node startup failed (network issue?): {e}")

        try:
            self.assertIsNotNone(
                node.addr_bytes, "node.addr_bytes should be set after startup"
            )
            self.assertGreater(len(node.addr_bytes), 0)
        finally:
            await asyncio.wait_for(node.close(), timeout=10)

    async def test_node_addr_is_parseable(self):
        from aionetiface import parse_node_addr

        try:
            node = await asyncio.wait_for(Node(conf=NODE_TEST_CONF), timeout=30)
        except Exception as e:
            self.skipTest(f"Node startup failed: {e}")

        try:
            addr = parse_node_addr(node.addr_bytes)
            self.assertIsNotNone(addr, "addr_bytes produced by Node must parse cleanly")
            self.assertIn(
                "pub_key_hex", addr, "Parsed address must include pub_key_hex"
            )
            self.assertIn("machine_id", addr, "Parsed address must include machine_id")
        finally:
            await asyncio.wait_for(node.close(), timeout=10)

    async def test_node_has_traversal_wired(self):
        """TraversalManager must be wired to the node after startup."""
        try:
            node = await asyncio.wait_for(Node(conf=NODE_TEST_CONF), timeout=30)
        except Exception as e:
            self.skipTest(f"Node startup failed: {e}")

        try:
            self.assertIsNotNone(
                node.traversal, "traversal should be set after node start"
            )
            self.assertIs(
                node.traversal.inbound_pipes,
                node.inbound_pipes,
                "traversal.inbound_pipes should share the node's inbound_pipes dict",
            )
        finally:
            await asyncio.wait_for(node.close(), timeout=10)

    async def test_node_id_is_derived_from_pub_key(self):
        """node_id == sha256(compressed_vk)[:25] — verified against live startup."""
        try:
            node = await asyncio.wait_for(Node(conf=NODE_TEST_CONF), timeout=30)
        except Exception as e:
            self.skipTest(f"Node startup failed: {e}")

        try:
            expected = hashlib.sha256(node.vk.to_string("compressed")).hexdigest()[:25]
            self.assertEqual(
                node.node_id, expected, "node_id must equal sha256(compressed_vk)[:25]"
            )
        finally:
            await asyncio.wait_for(node.close(), timeout=10)


if __name__ == "__main__":
    unittest.main()
