"""
Local-server TURN test using two distinct IPv4 loopback aliases.

The local TURNServer binds 127.0.0.1 *and* 127.0.0.2 (or whatever
extra alias probe_loopback_ips() picks up).  One client targets the
first bound IP, the other targets the second; the relay sockets are
bound on those same IPs, so the two clients see XorRelayedAddresses
on different loopback aliases.

Skipped on platforms that don't alias 127.0.0.x (notably macOS,
where only 127.0.0.1 is bindable by default).

Lives in its own subprocess per CLAUDE.md "Heavy tests live in
their own file".
"""

import asyncio
import unittest

from aionetiface import IP4, Interface
from aionetiface.testing import AsyncTestCase

from turn_helpers import (
    close_clients,
    close_server,
    relay_round_trip,
    start_local_turn,
    start_turn_client,
    whitelist_pair,
)


class TestTURNLoopbackAltIP(AsyncTestCase):
    """One client per loopback alias; relay round-trip across the two IPs."""

    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP4 not in self.nic.supported():
            self.skipTest("IPv4 not available on the default NIC")
        self.server = await start_local_turn(self, self.nic, IP4)
        ips = self.server.started_ips(IP4)
        if len(ips) < 2:
            await close_server(self.server)
            self.skipTest(
                "Only one IPv4 loopback alias available ({0}); platform doesn't "
                "support 127.0.0.x aliasing.".format(ips)
            )
        self.ip_a, self.ip_b = ips[0], ips[1]
        self.client_a = self.client_b = None

    async def asyncTearDown(self):
        await close_clients(self.client_a, self.client_b)
        await close_server(self.server)

    async def test_relay_across_loopback_aliases(self):
        port_a = self.server.port_for(IP4, self.ip_a)
        port_b = self.server.port_for(IP4, self.ip_b)

        self.client_a = await start_turn_client(IP4, (self.ip_a, port_a), self.nic)
        self.client_b = await start_turn_client(IP4, (self.ip_b, port_b), self.nic)

        a_relay = await self.client_a.relay_tup_future
        b_relay = await self.client_b.relay_tup_future
        self.assertEqual(
            a_relay[0], self.ip_a,
            "client_a's relay should be bound on its target IP",
        )
        self.assertEqual(
            b_relay[0], self.ip_b,
            "client_b's relay should be bound on its target IP",
        )
        self.assertNotEqual(
            a_relay[0], b_relay[0],
            "the two clients should have relays on different loopback aliases",
        )

        await whitelist_pair(self.client_a, self.client_b)

        out = await relay_round_trip(self.client_a, self.client_b, b"a->b alt")
        self.assertIsNotNone(
            out,
            "client_b never received a->b alt across loopback aliases",
        )
        self.assertIn(b"a->b alt", out)


if __name__ == "__main__":
    unittest.main()
