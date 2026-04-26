"""
Local-server TURN loopback test (IPv6, ::1).

Mirrors test_turn_loopback.py but over IPv6.  Skipped when ::1
isn't bindable on the host -- common in CI VMs that have IPv6
disabled or stripped from the loopback interface.

Lives in its own subprocess per CLAUDE.md "Heavy tests live in
their own file".
"""

import asyncio
import unittest

from aionetiface import IP6, Interface
from aionetiface.testing import AsyncTestCase

from turn_helpers import (
    close_clients,
    close_server,
    relay_round_trip,
    skip_on_windows_for_cross_loopback,
    start_local_turn,
    start_turn_client,
    whitelist_pair,
)


class TestTURNLoopbackIPv6(AsyncTestCase):
    """Two TURNClients on ::1 relay a payload through the local server."""

    async def asyncSetUp(self):
        # IPv6 ::1 from the default NIC source IP doesn't loop back
        # on Windows.  See turn_helpers.skip_on_windows_for_cross_loopback.
        skip_on_windows_for_cross_loopback(
            self,
            "IPv6 TURN loopback round-trip is Linux/macOS only "
            "until the FakeInterface.id SO_BINDTODEVICE crash is fixed.",
        )
        self.nic = await Interface()
        if IP6 not in self.nic.supported():
            self.skipTest("IPv6 not available on the default NIC")
        self.server = await start_local_turn(self, self.nic, IP6)
        self.client_a = self.client_b = None

    async def asyncTearDown(self):
        await close_clients(self.client_a, self.client_b)
        await close_server(self.server)

    async def test_relay_round_trip(self):
        port = self.server.port_for(IP6)
        if port is None:
            self.skipTest("TURN server bound IPv6 but reported no port")
        dest = ("::1", port)
        self.client_a = await start_turn_client(IP6, dest, self.nic)
        self.client_b = await start_turn_client(IP6, dest, self.nic)
        await whitelist_pair(self.client_a, self.client_b)

        out = await relay_round_trip(self.client_a, self.client_b, b"a->b v6")
        self.assertIsNotNone(out, "client_b never received a->b v6 through TURN")
        self.assertIn(b"a->b v6", out)


if __name__ == "__main__":
    unittest.main()
