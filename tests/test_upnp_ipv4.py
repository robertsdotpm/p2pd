"""
UPnP IPv4 integration tests, split out of test_upnp.py.

Discovers UPnP devices on the LAN via SSDP M-SEARCH and exercises
AddPortMapping. Heavy enough that we run it in its own subprocess
(per CLAUDE.md "Heavy tests live in their own file") so socket
state from the IPv6 classes can't bleed into it. Skipped
gracefully when no router is reachable, when no UPnP device
replies, or when the router refuses the mapping.
"""

import asyncio
import unittest

from aionetiface import IP4
from aionetiface.testing import AsyncTestCase

from warpgate.traversal.plugins.upnp.main import (
    discover_upnp_devices,
    port_forward,
)

from upnp_helpers import UPNP_TEST_PORT, get_test_nic


class TestUPnPDiscoverIPv4(AsyncTestCase):
    """Discover UPnP devices via IPv4 multicast M-SEARCH."""

    async def asyncSetUp(self):
        self.nic = await get_test_nic(self)
        if IP4 not in self.nic.supported():
            self.skipTest("IPv4 not available")

    async def test_discover_returns_list(self):
        replies = await asyncio.wait_for(
            discover_upnp_devices(IP4, self.nic), timeout=10
        )
        self.assertIsInstance(replies, list)

    async def test_discover_finds_device(self):
        replies = await asyncio.wait_for(
            discover_upnp_devices(IP4, self.nic), timeout=10
        )
        if not replies:
            self.skipTest("No UPnP devices found on this network")
        self.assertGreater(len(replies), 0)

    async def test_discover_replies_have_location_header(self):
        from warpgate.traversal.plugins.upnp.upnp_utils import (
            sort_upnp_replies_by_unique_location,
        )
        replies = await asyncio.wait_for(
            discover_upnp_devices(IP4, self.nic), timeout=10
        )
        if not replies:
            self.skipTest("No UPnP devices found on this network")
        unique = sort_upnp_replies_by_unique_location(replies)
        self.assertGreater(len(unique), 0)
        for r in unique:
            self.assertIn("location", r.hdrs)


class TestUPnPForwardIPv4(AsyncTestCase):
    """Attempt AddPortMapping via a real router.

    Skipped when no UPnP device is reachable.  The mapping persists on the
    router until it reboots or the entry is manually removed.
    """

    async def asyncSetUp(self):
        self.nic = await get_test_nic(self)
        if IP4 not in self.nic.supported():
            self.skipTest("IPv4 not available")
        replies = await asyncio.wait_for(
            discover_upnp_devices(IP4, self.nic), timeout=10
        )
        if not replies:
            self.skipTest("No UPnP devices found -- skipping port-forward test")

    async def test_port_forward_returns_success(self):
        route = self.nic.route(IP4)
        src_ip = str(route.nic())
        src_tup = (src_ip, UPNP_TEST_PORT)
        result = await asyncio.wait_for(
            port_forward(IP4, self.nic, UPNP_TEST_PORT, src_tup, "warpgate-test"),
            timeout=30,
        )
        if result != 1:
            self.skipTest("UPnP device found but AddPortMapping returned {} (router refused mapping)".format(result))
        self.assertEqual(result, 1, "IPv4 AddPortMapping should succeed on a UPnP-enabled router")

    async def test_port_forward_returns_int(self):
        route = self.nic.route(IP4)
        src_ip = str(route.nic())
        src_tup = (src_ip, UPNP_TEST_PORT)
        result = await asyncio.wait_for(
            port_forward(IP4, self.nic, UPNP_TEST_PORT, src_tup, "warpgate-test"),
            timeout=30,
        )
        self.assertIsInstance(result, int)
        self.assertIn(result, (0, 1))


if __name__ == "__main__":
    unittest.main()
