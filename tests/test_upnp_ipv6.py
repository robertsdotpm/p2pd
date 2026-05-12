"""
UPnP IPv6 integration tests, split out of test_upnp.py.

Discovers UPnP devices on the LAN via IPv6 multicast M-SEARCH
and exercises AddPinhole (RFC 6970). Skipped on hosts without
working IPv6, when no IPv6 UPnP device responds, or when the
router lacks WANIPv6FirewallControl. Lives in its own
subprocess (per CLAUDE.md "Heavy tests live in their own
file") so socket state from the IPv4 classes can't bleed in.
"""

import asyncio
import unittest

from aionetiface import IP6
from aionetiface.testing import AsyncTestCase

from warpgate.traversal.plugins.upnp.main import (
    discover_upnp_devices,
    port_forward,
)

from upnp_helpers import UPNP_TEST_PORT, get_test_nic


class TestUPnPDiscoverIPv6(AsyncTestCase):
    """Discover UPnP devices via IPv6 multicast M-SEARCH.

    Skipped when IPv6 is not available or when no IPv6 UPnP devices reply.
    Many routers support UPnP only over IPv4, so this commonly skips.
    """

    async def asyncSetUp(self):
        self.nic = await get_test_nic(self)
        if IP6 not in self.nic.supported():
            self.skipTest("IPv6 not available")

    async def test_discover_returns_list(self):
        replies = await asyncio.wait_for(
            discover_upnp_devices(IP6, self.nic), timeout=10
        )
        self.assertIsInstance(replies, list)

    async def test_discover_replies_have_location_if_any(self):
        from warpgate.traversal.plugins.upnp.upnp_utils import (
            sort_upnp_replies_by_unique_location,
        )
        replies = await asyncio.wait_for(
            discover_upnp_devices(IP6, self.nic), timeout=10
        )
        if not replies:
            self.skipTest("No IPv6 UPnP devices found")
        unique = sort_upnp_replies_by_unique_location(replies)
        self.assertGreater(len(unique), 0)
        for r in unique:
            self.assertIn("location", r.hdrs)


class TestUPnPForwardIPv6(AsyncTestCase):
    """Attempt AddPinhole via a real router.

    Skipped when IPv6 is unavailable, when no IPv6 UPnP device is found, or
    when the router doesn't support WANIPv6FirewallControl.  Routers that do
    not implement RFC 6970 return an error here and the test skips gracefully.
    """

    async def asyncSetUp(self):
        self.nic = await get_test_nic(self)
        if IP6 not in self.nic.supported():
            self.skipTest("IPv6 not available")
        replies = await asyncio.wait_for(
            discover_upnp_devices(IP6, self.nic), timeout=10
        )
        if not replies:
            self.skipTest("No IPv6 UPnP devices found -- skipping pin-hole test")

    async def test_port_forward_returns_int(self):
        route = self.nic.route(IP6)
        src_ip = str(route.ext())
        src_tup = (src_ip, UPNP_TEST_PORT)
        result = await asyncio.wait_for(
            port_forward(IP6, self.nic, UPNP_TEST_PORT, src_tup, "warpgate-test"),
            timeout=30,
        )
        self.assertIsInstance(result, int)
        self.assertIn(result, (0, 1))

    async def test_port_forward_succeeds_or_skips(self):
        route = self.nic.route(IP6)
        src_ip = str(route.ext())
        src_tup = (src_ip, UPNP_TEST_PORT)
        result = await asyncio.wait_for(
            port_forward(IP6, self.nic, UPNP_TEST_PORT, src_tup, "warpgate-test"),
            timeout=30,
        )
        if result == 0:
            self.skipTest("Router does not support WANIPv6FirewallControl (AddPinhole)")
        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
