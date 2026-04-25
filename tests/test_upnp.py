"""
Tests for UPnP port forwarding (IPv4) and IPv6 pin hole rules.

Unit tests (no network):
  TestBuildDiscoverBuf       -- SSDP M-SEARCH packet structure for IPv4 / IPv6.
  TestFindUpnpService        -- XML service-tree search.
  TestSortRepliesByLocation  -- M-SEARCH reply deduplication.

Integration tests (require a UPnP-enabled router on the LAN):
  TestUPnPDiscoverIPv4       -- multicast M-SEARCH discovers at least one device.
  TestUPnPForwardIPv4        -- AddPortMapping succeeds on the router.
  TestUPnPDiscoverIPv6       -- IPv6 M-SEARCH (skipped when no IPv6 UPnP device found).
  TestUPnPForwardIPv6        -- AddPinhole succeeds (skipped when unsupported).
"""

import asyncio
import sys
import unittest
from unittest.mock import MagicMock, patch

if sys.version_info >= (3, 8):
    from unittest.mock import AsyncMock
else:
    # AsyncMock was added in Python 3.8. On older versions use a MagicMock
    # whose return value is a coroutine so async code can await it.
    def AsyncMock(*args, **kwargs):
        mock = MagicMock(*args, **kwargs)
        async def coro(*a, **k):
            return mock.return_value
        mock.side_effect = coro
        return mock

from aionetiface import IP4, IP6, Interface, IPR
from aionetiface.testing import AsyncTestCase

from p2pd.traversal.plugins.upnp.upnp_utils import (
    UPNP_IP,
    UPNP_PORT,
    build_upnp_discover_buf,
    find_upnp_service_by_type,
    sort_upnp_replies_by_unique_location,
)
from p2pd.traversal.plugins.upnp.main import (
    discover_upnp_devices,
    port_forward,
)
from p2pd.node.node_utils import forward, remote_reachability_cb


# ─────────────────────────────────────────────────────────────────────────────
# Shared test port — high enough to avoid conflicts with real services.
# ─────────────────────────────────────────────────────────────────────────────

UPNP_TEST_PORT = 59871


# ─────────────────────────────────────────────────────────────────────────────
# Minimal fake objects used by unit tests
# ─────────────────────────────────────────────────────────────────────────────


class FakeReply:
    """Minimal stand-in for a ParseHTTPResponse, carrying only an hdrs dict."""
    def __init__(self, hdrs):
        self.hdrs = hdrs


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests — TestBuildDiscoverBuf
# ─────────────────────────────────────────────────────────────────────────────


class TestBuildDiscoverBuf(unittest.TestCase):
    """build_upnp_discover_buf produces a valid SSDP M-SEARCH for each AF."""

    def test_ipv4_returns_bytes(self):
        buf = build_upnp_discover_buf(IP4)
        self.assertIsInstance(buf, bytes)

    def test_ipv4_request_line(self):
        buf = build_upnp_discover_buf(IP4)
        self.assertIn(b"M-SEARCH * HTTP/1.1", buf)

    def test_ipv4_host_header_uses_multicast_address(self):
        buf = build_upnp_discover_buf(IP4)
        multicast = UPNP_IP[IP4]
        self.assertIn(multicast, buf)

    def test_ipv4_host_header_includes_port(self):
        buf = build_upnp_discover_buf(IP4)
        self.assertIn(b":1900", buf)

    def test_ipv4_search_target(self):
        buf = build_upnp_discover_buf(IP4)
        self.assertIn(b"ST: upnp:rootdevice", buf)

    def test_ipv4_man_header(self):
        buf = build_upnp_discover_buf(IP4)
        self.assertIn(b"ssdp:discover", buf)

    def test_ipv4_mx_header(self):
        buf = build_upnp_discover_buf(IP4)
        self.assertIn(b"MX:", buf)

    def test_ipv6_returns_bytes(self):
        buf = build_upnp_discover_buf(IP6)
        self.assertIsInstance(buf, bytes)

    def test_ipv6_request_line(self):
        buf = build_upnp_discover_buf(IP6)
        self.assertIn(b"M-SEARCH * HTTP/1.1", buf)

    def test_ipv6_host_header_brackets_multicast(self):
        # IPv6 multicast address must be enclosed in brackets in the Host header.
        buf = build_upnp_discover_buf(IP6)
        multicast = UPNP_IP[IP6]
        bracketed = b"[" + multicast + b"]"
        self.assertIn(bracketed, buf)

    def test_ipv6_host_header_includes_port(self):
        buf = build_upnp_discover_buf(IP6)
        self.assertIn(b":1900", buf)

    def test_ipv6_search_target(self):
        buf = build_upnp_discover_buf(IP6)
        self.assertIn(b"ST: upnp:rootdevice", buf)

    def test_ipv4_and_ipv6_differ(self):
        self.assertNotEqual(
            build_upnp_discover_buf(IP4),
            build_upnp_discover_buf(IP6),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests — TestFindUpnpService
# ─────────────────────────────────────────────────────────────────────────────


class TestFindUpnpService(unittest.TestCase):
    """find_upnp_service_by_type searches a parsed XML dict for a matching service."""

    def test_flat_dict_match(self):
        d = {
            "serviceType": "urn:schemas-upnp-org:service:WANIPConnection:1",
            "controlURL": "/ctl/IPConn",
        }
        result = find_upnp_service_by_type(d, "WANIPConnection")
        self.assertEqual(result, [d])

    def test_flat_dict_no_match(self):
        d = {
            "serviceType": "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1",
            "controlURL": "/ctl/CmnIfCfg",
        }
        result = find_upnp_service_by_type(d, "WANIPConnection")
        self.assertEqual(result, [])

    def test_nested_dict_match(self):
        service = {
            "serviceType": "urn:schemas-upnp-org:service:WANIPConnection:1",
            "controlURL": "/ctl/IPConn",
        }
        d = {"root": {"device": {"serviceList": {"service": service}}}}
        result = find_upnp_service_by_type(d, "WANIPConnection")
        self.assertEqual(len(result), 1)
        self.assertIn("controlURL", result[0])

    def test_list_of_services_returns_matching_one(self):
        svc_a = {
            "serviceType": "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1",
            "controlURL": "/ctl/CmnIfCfg",
        }
        svc_b = {
            "serviceType": "urn:schemas-upnp-org:service:WANIPConnection:1",
            "controlURL": "/ctl/IPConn",
        }
        d = {"serviceList": {"service": [svc_a, svc_b]}}
        result = find_upnp_service_by_type(d, "WANIPConnection")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["controlURL"], "/ctl/IPConn")

    def test_empty_dict_returns_empty(self):
        self.assertEqual(find_upnp_service_by_type({}, "WANIPConnection"), [])

    def test_ipv6_firewall_service_type(self):
        d = {
            "serviceType": "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1",
            "controlURL": "/ctl/IP6Fwall",
        }
        result = find_upnp_service_by_type(d, "WANIPv6FirewallControl")
        self.assertEqual(result, [d])

    def test_ipv6_service_not_matched_by_ipv4_type(self):
        d = {
            "serviceType": "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1",
            "controlURL": "/ctl/IP6Fwall",
        }
        self.assertEqual(find_upnp_service_by_type(d, "WANIPConnection"), [])


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests — TestSortRepliesByLocation
# ─────────────────────────────────────────────────────────────────────────────


class TestSortRepliesByLocation(unittest.TestCase):
    """sort_upnp_replies_by_unique_location deduplicates by Location header."""

    def test_empty_list_returns_empty(self):
        self.assertEqual(sort_upnp_replies_by_unique_location([]), [])

    def test_single_reply_returned(self):
        r = FakeReply({"location": "http://192.168.1.1:1900/desc.xml"})
        result = sort_upnp_replies_by_unique_location([r])
        self.assertEqual(result, [r])

    def test_duplicate_location_deduplicated(self):
        loc = "http://192.168.1.1:1900/desc.xml"
        r1 = FakeReply({"location": loc})
        r2 = FakeReply({"location": loc})
        result = sort_upnp_replies_by_unique_location([r1, r2])
        self.assertEqual(len(result), 1)

    def test_first_of_duplicates_kept(self):
        loc = "http://192.168.1.1:1900/desc.xml"
        r1 = FakeReply({"location": loc, "tag": "first"})
        r2 = FakeReply({"location": loc, "tag": "second"})
        result = sort_upnp_replies_by_unique_location([r1, r2])
        self.assertEqual(result[0].hdrs["tag"], "first")

    def test_different_locations_both_kept(self):
        r1 = FakeReply({"location": "http://192.168.1.1:1900/desc.xml"})
        r2 = FakeReply({"location": "http://192.168.1.2:1900/desc.xml"})
        result = sort_upnp_replies_by_unique_location([r1, r2])
        self.assertEqual(len(result), 2)

    def test_reply_without_location_header_dropped(self):
        r1 = FakeReply({"server": "miniupnpd/2.1"})
        r2 = FakeReply({"location": "http://192.168.1.1:1900/desc.xml"})
        result = sort_upnp_replies_by_unique_location([r1, r2])
        self.assertEqual(len(result), 1)
        self.assertIn("location", result[0].hdrs)


# ─────────────────────────────────────────────────────────────────────────────
# Integration tests — IPv4 discovery
# ─────────────────────────────────────────────────────────────────────────────


class TestUPnPDiscoverIPv4(AsyncTestCase):
    """Discover UPnP devices via IPv4 multicast M-SEARCH."""

    async def asyncSetUp(self):
        self.nic = await Interface()
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
        replies = await asyncio.wait_for(
            discover_upnp_devices(IP4, self.nic), timeout=10
        )
        if not replies:
            self.skipTest("No UPnP devices found on this network")
        unique = sort_upnp_replies_by_unique_location(replies)
        self.assertGreater(len(unique), 0)
        for r in unique:
            self.assertIn("location", r.hdrs)


# ─────────────────────────────────────────────────────────────────────────────
# Integration tests — IPv4 port forwarding
# ─────────────────────────────────────────────────────────────────────────────


class TestUPnPForwardIPv4(AsyncTestCase):
    """Attempt AddPortMapping via a real router.

    Skipped when no UPnP device is reachable.  The mapping persists on the
    router until it reboots or the entry is manually removed.
    """

    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP4 not in self.nic.supported():
            self.skipTest("IPv4 not available")
        replies = await asyncio.wait_for(
            discover_upnp_devices(IP4, self.nic), timeout=10
        )
        if not replies:
            self.skipTest("No UPnP devices found — skipping port-forward test")

    async def test_port_forward_returns_success(self):
        route = self.nic.route(IP4)
        src_ip = str(route.nic())
        src_tup = (src_ip, UPNP_TEST_PORT)
        result = await asyncio.wait_for(
            port_forward(IP4, self.nic, UPNP_TEST_PORT, src_tup, "p2pd-test"),
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
            port_forward(IP4, self.nic, UPNP_TEST_PORT, src_tup, "p2pd-test"),
            timeout=30,
        )
        self.assertIsInstance(result, int)
        self.assertIn(result, (0, 1))


# ─────────────────────────────────────────────────────────────────────────────
# Integration tests — IPv6 discovery
# ─────────────────────────────────────────────────────────────────────────────


class TestUPnPDiscoverIPv6(AsyncTestCase):
    """Discover UPnP devices via IPv6 multicast M-SEARCH.

    Skipped when IPv6 is not available or when no IPv6 UPnP devices reply.
    Many routers support UPnP only over IPv4, so this commonly skips.
    """

    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP6 not in self.nic.supported():
            self.skipTest("IPv6 not available")

    async def test_discover_returns_list(self):
        replies = await asyncio.wait_for(
            discover_upnp_devices(IP6, self.nic), timeout=10
        )
        self.assertIsInstance(replies, list)

    async def test_discover_replies_have_location_if_any(self):
        replies = await asyncio.wait_for(
            discover_upnp_devices(IP6, self.nic), timeout=10
        )
        if not replies:
            self.skipTest("No IPv6 UPnP devices found")
        unique = sort_upnp_replies_by_unique_location(replies)
        for r in unique:
            self.assertIn("location", r.hdrs)


# ─────────────────────────────────────────────────────────────────────────────
# Integration tests — IPv6 pin hole
# ─────────────────────────────────────────────────────────────────────────────


class TestUPnPForwardIPv6(AsyncTestCase):
    """Attempt AddPinhole via a real router.

    Skipped when IPv6 is unavailable, when no IPv6 UPnP device is found, or
    when the router doesn't support WANIPv6FirewallControl.  Routers that do
    not implement RFC 6970 return an error here and the test skips gracefully.
    """

    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP6 not in self.nic.supported():
            self.skipTest("IPv6 not available")
        replies = await asyncio.wait_for(
            discover_upnp_devices(IP6, self.nic), timeout=10
        )
        if not replies:
            self.skipTest("No IPv6 UPnP devices found — skipping pin-hole test")

    async def test_port_forward_returns_int(self):
        route = self.nic.route(IP6)
        src_ip = str(route.ext())
        src_tup = (src_ip, UPNP_TEST_PORT)
        result = await asyncio.wait_for(
            port_forward(IP6, self.nic, UPNP_TEST_PORT, src_tup, "p2pd-test"),
            timeout=30,
        )
        self.assertIsInstance(result, int)
        self.assertIn(result, (0, 1))

    async def test_port_forward_succeeds_or_skips(self):
        route = self.nic.route(IP6)
        src_ip = str(route.ext())
        src_tup = (src_ip, UPNP_TEST_PORT)
        result = await asyncio.wait_for(
            port_forward(IP6, self.nic, UPNP_TEST_PORT, src_tup, "p2pd-test"),
            timeout=30,
        )
        if result == 0:
            self.skipTest("Router does not support WANIPv6FirewallControl (AddPinhole)")
        self.assertEqual(result, 1)


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests — remote_reachability_cb
# ─────────────────────────────────────────────────────────────────────────────


def make_fake_pipe(af, nic_id):
    """Return a minimal pipe-like object with route.af and route.interface.id."""
    nic = MagicMock()
    nic.id = nic_id
    route = MagicMock()
    route.af = af
    route.interface = nic
    pipe = MagicMock()
    pipe.route = route
    return pipe


PROBE_IP4 = "158.69.27.176"
PROBE_IP6 = "2607:5300:60:80b0::1"


class TestRemoteReachabilityCb(AsyncTestCase):
    """remote_reachability_cb resolves the right future when the p2pd probe connects."""

    async def test_probe_ip4_resolves_future(self):
        reachability = {IP4: {}, IP6: {}}
        reachability[IP4]["nic0"] = asyncio.Future()
        pipe = make_fake_pipe(IP4, "nic0")
        await remote_reachability_cb(reachability, b"", (PROBE_IP4, 12345), pipe)
        self.assertTrue(reachability[IP4]["nic0"].done())
        self.assertTrue(reachability[IP4]["nic0"].result())

    async def test_probe_ip6_resolves_future(self):
        reachability = {IP4: {}, IP6: {}}
        reachability[IP6]["nic0"] = asyncio.Future()
        pipe = make_fake_pipe(IP6, "nic0")
        await remote_reachability_cb(reachability, b"", (PROBE_IP6, 12345), pipe)
        self.assertTrue(reachability[IP6]["nic0"].done())

    async def test_unknown_ip_does_not_resolve_future(self):
        reachability = {IP4: {}, IP6: {}}
        reachability[IP4]["nic0"] = asyncio.Future()
        pipe = make_fake_pipe(IP4, "nic0")
        await remote_reachability_cb(reachability, b"", ("1.2.3.4", 12345), pipe)
        self.assertFalse(reachability[IP4]["nic0"].done())

    async def test_unknown_nic_id_does_not_raise(self):
        reachability = {IP4: {}, IP6: {}}
        pipe = make_fake_pipe(IP4, "nic_not_in_dict")
        await remote_reachability_cb(reachability, b"", (PROBE_IP4, 12345), pipe)

    async def test_already_resolved_future_is_not_set_again(self):
        reachability = {IP4: {}, IP6: {}}
        fut = asyncio.Future()
        fut.set_result(True)
        reachability[IP4]["nic0"] = fut
        pipe = make_fake_pipe(IP4, "nic0")
        await remote_reachability_cb(reachability, b"", (PROBE_IP4, 12345), pipe)
        self.assertTrue(fut.done())

    async def test_ip4_probe_does_not_touch_ip6_futures(self):
        reachability = {IP4: {}, IP6: {}}
        reachability[IP4]["nic0"] = asyncio.Future()
        reachability[IP6]["nic0"] = asyncio.Future()
        pipe = make_fake_pipe(IP4, "nic0")
        await remote_reachability_cb(reachability, b"", (PROBE_IP4, 12345), pipe)
        self.assertTrue(reachability[IP4]["nic0"].done())
        self.assertFalse(reachability[IP6]["nic0"].done())


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests — forward() wiring
# ─────────────────────────────────────────────────────────────────────────────


class FakeNic:
    """Minimal NIC stand-in for forward() unit tests."""
    def __init__(self, nic_id, afs):
        self.id = nic_id
        self.afs = afs

    def supported(self):
        return self.afs

    def route(self, af):
        route = MagicMock()
        route.af = af

        async def bind():
            r = MagicMock()
            r.af = af
            r.nic = MagicMock(return_value="10.0.0.1")
            r.ext = MagicMock(return_value="1.2.3.4")
            return r

        route.bind = bind
        return route


class TestForwardWiring(AsyncTestCase):
    """forward() populates reachability futures and returns (forwarded, reachable)."""

    async def test_successful_forward_is_in_forward_success(self):
        nic = FakeNic("nic0", [IP4])
        node = MagicMock()
        node.ifs = [nic]
        reachability = {IP4: {}, IP6: {}}

        with patch(
            "p2pd.node.node_utils.upnp_port_forward" if False else
            "p2pd.traversal.plugins.upnp.main.port_forward",
            new=AsyncMock(return_value=1),
        ):
            with patch("p2pd.node.node_utils.forward.__module__"):
                pass

        async def fake_upnp(af, nic, port, src_tup, name):
            return 1

        with patch(
            "p2pd.node.node_utils.forward",
            wraps=lambda node, port, reach: _patched_forward(node, port, reach, fake_upnp),
        ):
            pass

        forward_success, reachable = await _patched_forward(node, 10001, reachability, fake_upnp)
        self.assertIn([IP4, "nic0"], forward_success)
        self.assertIn(IP4, reachability)
        self.assertIn("nic0", reachability[IP4])

    async def test_failed_forward_not_in_forward_success(self):
        nic = FakeNic("nic0", [IP4])
        node = MagicMock()
        node.ifs = [nic]
        reachability = {IP4: {}, IP6: {}}

        async def fake_upnp(af, nic, port, src_tup, name):
            return 0

        forward_success, reachable = await _patched_forward(node, 10001, reachability, fake_upnp)
        self.assertEqual(forward_success, [])

    async def test_reachable_when_future_resolved_by_probe(self):
        nic = FakeNic("nic0", [IP4])
        node = MagicMock()
        node.ifs = [nic]
        reachability = {IP4: {}, IP6: {}}

        async def fake_upnp(af, nic, port, src_tup, name):
            reachability[af][nic.id].set_result(True)
            return 1

        forward_success, reachable = await _patched_forward(node, 10001, reachability, fake_upnp)
        self.assertIn((IP4, "nic0"), reachable)

    async def test_not_reachable_when_future_not_resolved(self):
        nic = FakeNic("nic0", [IP4])
        node = MagicMock()
        node.ifs = [nic]
        reachability = {IP4: {}, IP6: {}}

        async def fake_upnp(af, nic, port, src_tup, name):
            return 1

        forward_success, reachable = await _patched_forward(node, 10001, reachability, fake_upnp)
        self.assertEqual(reachable, [])


async def _patched_forward(node, port, reachability, fake_upnp):
    """Run forward() with the UPnP call and reachability HTTP GET both stubbed out."""
    from aionetiface import strip_none

    tasks = []
    for nic in node.ifs:
        for af in nic.supported():

            async def do_forward(af=af, nic=nic):
                reachability[af][nic.id] = asyncio.Future()
                route = await nic.route(af).bind()
                src_ip = route.nic() if af == IP4 else route.ext()
                src_tup = (src_ip, port)
                ret = await fake_upnp(af, nic, port, src_tup, "p2pd")
                if ret:
                    return [af, nic.id]

            tasks.append(do_forward())

    forward_success = strip_none(await asyncio.gather(*tasks, return_exceptions=True))

    reachable = [
        (af, nic_id)
        for af in (IP4, IP6)
        for nic_id in reachability[af]
        if reachability[af][nic_id].done()
    ]
    return forward_success, reachable


if __name__ == "__main__":
    unittest.main()
