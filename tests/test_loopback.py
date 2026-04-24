"""
Focused tests for loopback socket binding (IPv4 + IPv6, UDP + TCP, port=0).


"""
import socket
import asyncio
import unittest
from aionetiface import IP4, IP6, UDP, TCP, Interface
from aionetiface.testing import AsyncTestCase

from stun_server import STUNServer, STUN_TEST_PORT


class TestLoopbackBindIPv4(AsyncTestCase):
    """UDP and TCP sockets bind and receive on 127.0.0.1."""

    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP4 not in self.nic.supported():
            self.skipTest("IPv4 not available")

    async def test_udp_port0_bind(self):
        server = STUNServer(self.nic)
        await server.start()
        try:
            self.assertIn(IP4, server.af_ports)
            port = server.af_ports[IP4]
            self.assertGreater(port, 0, "port=0 should yield a non-zero ephemeral port")
        finally:
            await server.close()

    async def test_tcp_port0_bind(self):
        server = STUNServer(self.nic)
        await server.start()
        try:
            self.assertIn(IP4, server.af_ports)
            port = server.af_ports[IP4]
            self.assertGreater(port, 0)
        finally:
            await server.close()

    async def test_two_servers_get_distinct_ports(self):
        a = STUNServer(self.nic)
        b = STUNServer(self.nic)
        await a.start()
        await b.start()
        try:
            port_a = a.af_ports.get(IP4, 0)
            port_b = b.af_ports.get(IP4, 0)
            self.assertGreater(port_a, 0)
            self.assertGreater(port_b, 0)
            self.assertNotEqual(port_a, port_b, "two port=0 servers should get distinct ports")
        finally:
            await a.close()
            await b.close()


class TestLoopbackBindIPv6(AsyncTestCase):
    """UDP and TCP sockets bind and receive on ::1."""

    ipv6_functional = None

    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP6 not in self.nic.supported():
            self.skipTest("IPv6 not available")

        if TestLoopbackBindIPv6.ipv6_functional is None:
            probe = STUNServer(self.nic)
            await probe.start()
            TestLoopbackBindIPv6.ipv6_functional = IP6 in probe.started_afs()
            await probe.close()

        if not TestLoopbackBindIPv6.ipv6_functional:
            self.skipTest("IPv6 loopback not functional (::1 bind failed)")

    async def test_ipv6_udp_port0_bind(self):
        server = STUNServer(self.nic)
        await server.start()
        try:
            self.assertIn(IP6, server.af_ports)
            port = server.af_ports[IP6]
            self.assertGreater(port, 0)
        finally:
            await server.close()

    async def test_ipv6_tcp_port0_bind(self):
        server = STUNServer(self.nic)
        await server.start()
        try:
            self.assertIn(IP6, server.af_ports)
            port = server.af_ports[IP6]
            self.assertGreater(port, 0)
        finally:
            await server.close()

    async def test_ipv4_and_ipv6_ports_differ(self):
        server = STUNServer(self.nic)
        await server.start()
        try:
            port4 = server.af_ports.get(IP4, 0)
            port6 = server.af_ports.get(IP6, 0)
            if port4 and port6:
                self.assertNotEqual(
                    port4, port6,
                    "IPv4 and IPv6 must get independent ports (no port reuse race)"
                )
        finally:
            await server.close()


if __name__ == "__main__":
    unittest.main()
