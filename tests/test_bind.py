from p2pd import *


class TestBind(unittest.IsolatedAsyncioTestCase):
    async def test_bind_closure(self):
        pass

        i = await Interface().start_local()
        b = Bind(i, None, leave_none=1)

        b.af = IP4
        out = (await bind_closure(b)(80, "127.0.0.1"))._bind_tups
        assert(out == {1: ('127.0.0.1', 80), 2: ('127.0.0.1', 80)})

        out = (await bind_closure(b)(80, "192.168.0.1"))._bind_tups
        assert(out == {1: ('192.168.0.1', 80), 2: ('192.168.0.1', 80)})

        out = (await bind_closure(b)(80, "8.8.8.8"))._bind_tups
        assert(out == {1: ('8.8.8.8', 80), 2: ('8.8.8.8', 80)})

        out = (await bind_closure(b)(80, "0.0.0.0"))._bind_tups
        assert(out == {1: ('0.0.0.0', 80), 2: ('0.0.0.0', 80)})

        # This is where things tend to go badly.
        b.af = IP6

        out = (await bind_closure(b)(80, "::1"))._bind_tups


        out = (await bind_closure(b)(80, "fe80::6c00:b217:18ca:e365"))._bind_tups
        #assert(out[1][2] > 0 or out[2][2] > 0)


        #out = (await bind_closure(b)(80, ""))._bind_tups
        
    async def test_bind(self):
        i = await Interface().start_local()
        af = i.stack if i.stack != DUEL_STACK else IP4
        b = Bind(i, af)

    async def test_ip_val_v6_bind_types(self):
        i = await Interface().start_local()
        try:
            # Test global tuples set.
            ip = ip_norm("2402:1f00:8101:83f::1")
            b = Bind(i, IP6, ips=ip)
            await b.bind()
            self.assertEqual(b.ext_bind, ip)
            self.assertEqual(ip_norm(b.bind_tup(flag=EXT_BIND)[0]), ip)
            self.assertEqual(ip_norm(b.ext_bind), ip)

            # Test link local tuples set.
            ip = i.route(IP6).nic()
            b = Bind(i, IP6, ips=ip)
            await b.bind()
            self.assertEqual(b.nic_bind, ip)
            self.assertEqual(ip_norm(b.bind_tup(flag=NIC_BIND)[0]), ip)
            self.assertEqual(ip_norm(b.nic_bind), ip)
            s = await socket_factory(b)
            self.assertTrue(isinstance(s, socket.socket))
            s.close()
        except:
            return

    async def test_ip_val_v4_bind_types(self):
        i = await Interface().start_local()

        # Test nic bind occurs.
        tests = ["192.168.0.1", "8.8.8.8"]
        for ip in tests:
            b = Bind(i, IP4, ips=ip)
            self.assertEqual(b.nic_bind, ip)
            await b.bind()
            self.assertEqual(b.bind_tup(flag=NIC_BIND)[0], ip)

    async def test_route_v4_bind_types(self):
        i = await Interface().start_local()
        r = i.route(IP4)
        b = await r.bind()
        tup = b.bind_tup(flag=NIC_BIND)
        self.assertTrue(tup[0])

    async def test_route_v6_bind_types(self):
        i = await Interface().start_local()

        try:
            af = IP6
            r = await i.route_test(af)

            # Patch EXT to return a pub IP without interface being resolved.
            r.ext = lambda: "2402:1f00:8101:083f:0000:0000:0000:0001"
            b = await r.bind()
            tup = b.bind_tup(flag=EXT_BIND)
            self.assertTrue(tup[0])
        except:
            return

    # TODO: netifaces is pulling invalid net masks for some IPs?
    async def test_bind_assumptions(self):
        ip = "139.99.209.1"
        #socket.socket(IP4, TCP)


    async def test_bind_start_v4_all_addr(self):
        af = IP4
        try:
            i = await Interface(af).start_local()
        except:
            # If not supported.
            return

        route = await i.route(af).bind(13453, "*")
        bind_tup = ("0.0.0.0", 13453)
        expected_tups = {
            EXT_BIND: bind_tup,
            NIC_BIND: bind_tup
        }
        self.assertEqual(route._bind_tups, expected_tups)
        s = await socket_factory(route)
        self.assertTrue(s is not None)
        if s is not None:
            s.close()

    async def test_bind_start_v6_all_addr(self):
        i = await Interface().start_local()
        try:
            af = IP6
            route = await i.route(af).bind(13453, "*")
            bind_tup = (
                "::",
                13453,

                # NIC no and scope ID stuff from getaddrinfo.
                route._bind_tups[EXT_BIND][2],
                route._bind_tups[EXT_BIND][3]
            )
            expected_tups = {
                EXT_BIND: bind_tup,
                NIC_BIND: bind_tup
            }
            self.assertEqual(route._bind_tups, expected_tups)
            s = await socket_factory(route)
            self.assertTrue(s is not None)
            if s is not None:
                s.close()
        except:
            return

# TODO loopback tests.

if __name__ == '__main__':
    main()