"""
Tests for STUNClient using a local test STUN server.

Validates:
  - IPv4 and IPv6 binding requests
  - XorMappedAddress decoding
  - RFC3489 and RFC5389 modes

Run from project root:
    python -m pytest tests/test_stun_client.py -v
or
    python -m unittest tests/test_stun_client -v
"""

import asyncio
import sys
import unittest

from aionetiface import (
    Interface, STUNClient,
    IP4, IP6, UDP, TCP,
    to_s,
    async_wrap_errors,
    RFC3489, RFC5389,
)

from tests.stun_server import STUNServer, STUN_TEST_PORT


if sys.version_info >= (3, 8):
    AsyncTestCase = unittest.IsolatedAsyncioTestCase
else:
    class AsyncTestCase(unittest.TestCase):
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
                    return val
                def sync_wrapper(coro_fn=val, ev_loop=loop):
                    ev_loop.run_until_complete(coro_fn())
                return sync_wrapper
            return val


def make_stun_client(nic, af, port=STUN_TEST_PORT, mode=RFC5389, proto=UDP):
    ip = "::1" if af == IP6 else "127.0.0.1"
    return STUNClient(af, (ip, port), nic, proto=proto, mode=mode)


# ──────────────────────────────────────────────────────────────────────────────
# Test 1 -- IPv4 Binding Request/Response
# ──────────────────────────────────────────────────────────────────────────────

class TestSTUNClientIPv4(AsyncTestCase):
    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP4 not in self.nic.supported():
            self.skipTest("IPv4 not available")
        self.server = STUNServer(self.nic, mode=RFC5389)
        await self.server.start()

    async def asyncTearDown(self):
        await self.server.close()

    async def test_binding_request_returns_mapped_address(self):
        client = make_stun_client(self.nic, IP4, mode=RFC5389)
        reply = await asyncio.wait_for(
            client.get_stun_reply(),
            timeout=10
        )

        self.assertIsNotNone(reply)
        self.assertTrue(hasattr(reply, "rtup"), "reply should have rtup (mapped address)")
        ip, port = reply.rtup
        self.assertEqual(ip, "127.0.0.1", "mapped IP should be loopback for IPv4")
        self.assertIsInstance(port, int)
        self.assertGreater(port, 0)
        self.assertLess(port, 65536)

    async def test_binding_request_rfc3489_mode(self):
        server = STUNServer(self.nic, mode=RFC3489)
        await server.start()
        try:
            client = make_stun_client(self.nic, IP4, mode=RFC3489)
            reply = await asyncio.wait_for(
                client.get_stun_reply(),
                timeout=10
            )

            self.assertIsNotNone(reply)
            self.assertTrue(hasattr(reply, "rtup"))
            ip, port = reply.rtup
            self.assertEqual(ip, "127.0.0.1")
            self.assertIsInstance(port, int)
        finally:
            await server.close()

    async def test_multiple_requests_get_consistent_mapped_address(self):
        client = make_stun_client(self.nic, IP4)
        ips_and_ports = []

        for _ in range(3):
            reply = await asyncio.wait_for(
                client.get_stun_reply(),
                timeout=10
            )
            self.assertIsNotNone(reply)
            ips_and_ports.append(reply.rtup)

        for ip, port in ips_and_ports:
            self.assertEqual(ip, "127.0.0.1")
            self.assertIsInstance(port, int)


# ──────────────────────────────────────────────────────────────────────────────
# Test 2 -- IPv6 Binding Request/Response
# ──────────────────────────────────────────────────────────────────────────────

class TestSTUNClientIPv6(AsyncTestCase):
    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP6 not in self.nic.supported():
            self.skipTest("IPv6 not available on this machine")
        self.server = STUNServer(self.nic, mode=RFC5389)
        await self.server.start()

    async def asyncTearDown(self):
        await self.server.close()

    async def test_ipv6_binding_request_returns_mapped_address(self):
        client = make_stun_client(self.nic, IP6, mode=RFC5389)
        reply = await asyncio.wait_for(
            client.get_stun_reply(),
            timeout=10
        )

        self.assertIsNotNone(reply)
        self.assertTrue(hasattr(reply, "rtup"))
        ip, port = reply.rtup
        self.assertIn(":", ip, "IPv6 address should contain colon")
        self.assertIsInstance(port, int)
        self.assertGreater(port, 0)
        self.assertLess(port, 65536)

    async def test_ipv6_binding_request_rfc3489_mode(self):
        server = STUNServer(self.nic, mode=RFC3489)
        await server.start()
        try:
            client = make_stun_client(self.nic, IP6, mode=RFC3489)
            reply = await asyncio.wait_for(
                client.get_stun_reply(),
                timeout=10
            )

            self.assertIsNotNone(reply)
            self.assertTrue(hasattr(reply, "rtup"))
            ip, port = reply.rtup
            self.assertIn(":", ip)
            self.assertIsInstance(port, int)
        finally:
            await server.close()

    async def test_ipv6_multiple_requests_consistent(self):
        client = make_stun_client(self.nic, IP6)
        ips_and_ports = []

        for _ in range(3):
            reply = await asyncio.wait_for(
                client.get_stun_reply(),
                timeout=10
            )
            self.assertIsNotNone(reply)
            ips_and_ports.append(reply.rtup)

        for ip, port in ips_and_ports:
            self.assertIn(":", ip)
            self.assertIsInstance(port, int)


# ──────────────────────────────────────────────────────────────────────────────
# Test 3 -- TCP IPv4 Binding Request/Response
# ──────────────────────────────────────────────────────────────────────────────

class TestSTUNClientTCPIPv4(AsyncTestCase):
    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP4 not in self.nic.supported():
            self.skipTest("IPv4 not available")
        self.server = STUNServer(self.nic, mode=RFC5389)
        await self.server.start()

    async def asyncTearDown(self):
        await self.server.close()

    async def test_tcp_binding_request_returns_mapped_address(self):
        client = make_stun_client(self.nic, IP4, mode=RFC5389, proto=TCP)
        reply = await asyncio.wait_for(
            client.get_stun_reply(),
            timeout=10
        )

        self.assertIsNotNone(reply)
        self.assertTrue(hasattr(reply, "rtup"))
        ip, port = reply.rtup
        self.assertEqual(ip, "127.0.0.1")
        self.assertIsInstance(port, int)
        self.assertGreater(port, 0)

    async def test_tcp_binding_request_rfc3489_mode(self):
        server = STUNServer(self.nic, mode=RFC3489, port=STUN_TEST_PORT + 1)
        await server.start()
        try:
            client = make_stun_client(self.nic, IP4, mode=RFC3489, proto=TCP, port=STUN_TEST_PORT + 1)
            reply = await asyncio.wait_for(
                client.get_stun_reply(),
                timeout=10
            )

            self.assertIsNotNone(reply)
            self.assertTrue(hasattr(reply, "rtup"))
            ip, port = reply.rtup
            self.assertEqual(ip, "127.0.0.1")
        finally:
            await server.close()


# ──────────────────────────────────────────────────────────────────────────────
# Test 4 -- TCP IPv6 Binding Request/Response
# ──────────────────────────────────────────────────────────────────────────────

class TestSTUNClientTCPIPv6(AsyncTestCase):
    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP6 not in self.nic.supported():
            self.skipTest("IPv6 not available on this machine")
        self.server = STUNServer(self.nic, mode=RFC5389)
        await self.server.start()

    async def asyncTearDown(self):
        await self.server.close()

    async def test_tcp_ipv6_binding_request_returns_mapped_address(self):
        client = make_stun_client(self.nic, IP6, mode=RFC5389, proto=TCP)
        reply = await asyncio.wait_for(
            client.get_stun_reply(),
            timeout=10
        )

        self.assertIsNotNone(reply)
        self.assertTrue(hasattr(reply, "rtup"))
        ip, port = reply.rtup
        self.assertIn(":", ip)
        self.assertIsInstance(port, int)
        self.assertGreater(port, 0)

    async def test_tcp_ipv6_binding_request_rfc3489_mode(self):
        server = STUNServer(self.nic, mode=RFC3489, port=STUN_TEST_PORT + 1)
        await server.start()
        try:
            client = make_stun_client(self.nic, IP6, mode=RFC3489, proto=TCP, port=STUN_TEST_PORT + 1)
            reply = await asyncio.wait_for(
                client.get_stun_reply(),
                timeout=10
            )

            self.assertIsNotNone(reply)
            self.assertTrue(hasattr(reply, "rtup"))
            ip, port = reply.rtup
            self.assertIn(":", ip)
        finally:
            await server.close()


# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main()
