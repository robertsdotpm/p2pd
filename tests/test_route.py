from p2pd import *


class TestRoute(unittest.IsolatedAsyncioTestCase):
    async def test_invalid_wan(self):
        def ambiguous_af_ip():
            IPRange(0)

        # If zero is passed do you want a V4 or V5 -- the netmask tells which.
        self.assertRaises(Exception, ambiguous_af_ip)

        # Check netmask works for V4.
        ipr = IPRange(0, netmask="255.255.255.255")
        self.assertEqual(len(ipr), 1)
        self.assertEqual(str(ipr[0]), "0.0.0.0")

        # Check netmask works for V6.
        ip = "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"
        ipr = IPRange(0, netmask=ip)
        self.assertEqual(str(ipr[0]), "::")

        # Test invalid WAN is detected.
        ipr_nic = IPRange("192.168.0.20")
        def invalid_wan():
            ipr_wan = IPRange(0, "255.255.255.255")
            route = Route(IP4, [ipr_nic], [ipr_wan])

        self.assertRaises(Exception, invalid_wan)

    async def test_bind_to_route(self):
        i = await Interface()
        b = await Bind(i, i.supported()[0]).bind()
        r = await bind_to_route(b)

    async def test_if_to_rp(self):
        i = await Interface()
        rp = interfaces_to_rp([i])

    async def test_netiface_addr_to_ipr(self):
        loop = asyncio.get_event_loop()
        i = await Interface()
        af = i.supported()[0]
        r = i.route(af)
        info = {
            "addr": str(r.nic_ips[0]),
            "netmask": cidr_to_netmask(r.nic_ips[0].cidr, af)
        }

        ipr = await netiface_addr_to_ipr(af, i.id, info)
        self.assertTrue(ipr is not None)


    async def test_route_ops(self):
        r1 = Route(
            af=IP4,
            nic_ips=[IPRange("192.168.0.1")],
            ext_ips=[IPRange("8.8.8.8")]
        )
        self.assertEqual(len(r1), 1)
        self.assertEqual(r1, r1)

        r2 = Route(
            af=IP4,
            nic_ips=[IPRange("192.168.0.10")],
            ext_ips=[IPRange("8.8.8.8")]
        )

        r3 = Route(
            af=IP4,
            nic_ips=[IPRange("192.168.0.10")],
            ext_ips=[IPRange("8.8.8.10")]
        )
        self.assertNotEqual(r1, r3  )

        r4 = Route(
            af=IP4,
            nic_ips=[IPRange("192.168.0.10")],
            ext_ips=[IPRange("8.8.8.12")]
        )

        r5 = Route(
            af=IP6,
            nic_ips=[IPRange("2402:1f00:8101:83f::1")],
            ext_ips=[IPRange("2402:1f00:8101:83f::1")]
        )

        rp = RoutePool([r1, r2, r3, r4, r5])
        nic_ipr_a = IPRange("192.168.0.2")
        nic_ipr_b = IPRange("192.168.0.1")
        ipr_c = IPRange("8.8.8.8")
        ipr_d = IPRange("2402:1f00:8101:83f::2")

        # Can find NIC properly.
        self.assertFalse(r1.has_nic_ip(nic_ipr_a))
        self.assertTrue(r1.has_nic_ip(nic_ipr_b))

        # Test equality (same ext = same route)
        self.assertEqual(r1, r2)
        self.assertTrue(r1 in r2)

        # Test invert (find route with different wan ip).
        r = ~r1
        self.assertTrue(r.ext_ips[0] != ipr_c)
        
        # Test not equal.
        self.assertTrue(r != r1)

        # Get N alternative routes that use a different IP.
        # Exclusions are supported.
        exclusions = [r3]
        routes = r1.alt(limit=10, exclusions=exclusions)
        self.assertTrue(len(routes))
        self.assertFalse(r1 in routes)
        self.assertFalse(r3 in routes)

        # Check all different conversions.
        self.assertFalse(r4 == ipr_c) # IPRange
        self.assertFalse(r4 == "10.0.0.1") # Str
        self.assertFalse(r4 == b"10.0.0.1") # bytes
        self.assertFalse(r5 == int(ipr_d)) # int
        self.assertFalse(r4 == ipaddress.IPv4Address(1)) # IPaddress

        # Check route pool iter code.
        i = 0
        for route in rp:
            self.assertTrue(isinstance(route, Route))
            i += 1
            if i >= 2:
                break

        # Check reversed works.
        i = 0
        for route in reversed(rp):
            self.assertTrue(isinstance(route, Route))
            i += 1
            if i >= 2:
                break

    async def test_route_pool(self):
        # 511 hosts overall
        af = IP4
        ipr_a = IPRange("8.8.8.0", cidr=24) # 255 hosts
        ipr_b = IPRange("7.7.7.0", cidr=24) # 255 hosts
        ipr_c = IPRange("9.9.9.9") # 1 host
        
        # Setup route pool
        r1 = Route(af, [ipr_a], [copy.deepcopy(ipr_a)])
        r2 = Route(af, [ipr_b], [copy.deepcopy(ipr_b)])
        r3 = Route(af, [ipr_c], [copy.deepcopy(ipr_c)])
        rp = RoutePool([r1, r2, r3])

        # Test dict serialization.
        d = rp.to_dict()
        rp = RoutePool.from_dict(d)

        # block a + block b + 1 host = 511
        self.assertEqual(rp.wan_hosts, 511)
        self.assertEqual(len(rp), 511)

        # Index a host into first range.
        ipr_x = IPRange("8.8.8.11")
        self.assertEqual(rp[10], ipr_x)

        # Index a host into second range.
        ipr_x = IPRange("7.7.7.11")
        self.assertEqual(rp[265], ipr_x)

        # Try index last host in range using negative index.
        self.assertEqual(rp[-1], ipr_c)

        # Test slicing between ranges.
        x = rp[254:256]
        self.assertEqual(len(x), 2)
        self.assertEqual(x[0].ext_ips[0], IPRange("8.8.8.255"))
        self.assertEqual(x[1].ext_ips[0], IPRange("7.7.7.1")) 

        # Test tuple list fetching.
        x = rp[(254, 255)]
        self.assertEqual(len(x), 2)
        self.assertEqual(x[0].ext_ips[0], IPRange("8.8.8.255"))
        self.assertEqual(x[1].ext_ips[0], IPRange("7.7.7.1")) 

        # Test reversed iter.
        for r in reversed(rp):
            self.assertEqual(r.ext_ips[0], ipr_c)
            break

        # Test regular iter.
        for r in rp:
            self.assertEqual(r.ext_ips[0], IPRange("8.8.8.1"))
            break

        # Test pop.
        x = rp.pop()
        self.assertEqual(x.ext_ips[0], IPRange("8.8.8.1"))
        x = rp.pop()
        self.assertEqual(x.ext_ips[0], IPRange("8.8.8.2"))

if __name__ == '__main__':
    main()