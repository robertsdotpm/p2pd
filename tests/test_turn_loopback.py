"""
Local-server TURN loopback test (IPv4, single IP).

Two TURNClient instances connect to the local TURNServer on
127.0.0.1.  Each gets its own ephemeral source port and own relay
allocation; they whitelist each other and exchange a short payload
through the relay.

Lives in its own subprocess (per CLAUDE.md "Heavy tests live in
their own file") so socket / asyncio churn from the IPv6 and
multi-IP variants can't flake this one.
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


class TestTURNLoopback(AsyncTestCase):
    """Two TURNClients on 127.0.0.1 relay a payload through the local server."""

    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP4 not in self.nic.supported():
            self.skipTest("IPv4 not available on the default NIC")
        self.server = await start_local_turn(self, self.nic, IP4)
        self.client_a = self.client_b = None

    async def asyncTearDown(self):
        await close_clients(self.client_a, self.client_b)
        await close_server(self.server)

    async def test_relay_round_trip(self):
        port = self.server.port_for(IP4)
        dest = ("127.0.0.1", port)
        self.client_a = await start_turn_client(IP4, dest, self.nic)
        self.client_b = await start_turn_client(IP4, dest, self.nic)
        await whitelist_pair(self.client_a, self.client_b)

        out = await relay_round_trip(self.client_a, self.client_b, b"a->b")
        self.assertIsNotNone(out, "client_b never received a->b through the TURN relay")
        self.assertIn(b"a->b", out)

        out = await relay_round_trip(self.client_b, self.client_a, b"b->a")
        self.assertIsNotNone(out, "client_a never received b->a through the TURN relay")
        self.assertIn(b"b->a", out)


if __name__ == "__main__":
    unittest.main()
