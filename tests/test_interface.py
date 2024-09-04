from p2pd import *

class TestInterface(unittest.IsolatedAsyncioTestCase):
    async def test_regular(self):
        i = await Interface()
        print(i)
        loop = asyncio.get_event_loop()
        print(loop)
        await asyncio.sleep(5)


    async def test_fallback_zero_bind(self):
        return
        # TODO: figure out how to test htis

        # The default interface.
        i = Interface()

        # Make sure the interface loads its regular netifaces.
        # As the call about modifies this state.
        Interface.get_netifaces = lambda: None

        # The get_routes func will get zero IF ips.
        netifaces.ifaddresses = lambda x: {IP4: [], IP6: []}

        # Use the patches netifaces for route resolution.
        await i.start()

        # Now ensure there's a fallback route.
        af = i.supported()[0]
        cidr = af_to_cidr(af)
        route = i.route(af)

        # The fallbacks nic ip should be on the any addr.
        nic_ipr = IPRange(ANY_ADDR_LOOKUP[af], cidr=cidr)
        assert(route.nic_ips[0] == nic_ipr)

        # While its ext IP should be public.
        assert(route.ext_ips[0].is_public)
        

    # Should find at least a valid iface on whatever OS.
    async def test_default_interface(self):
        i = await Interface()
        self.assertTrue(i.name)

        i = await Interface("")
        self.assertTrue(i.name)

        i = await Interface(AF_ANY)
        self.assertTrue(i.name)

        i = await Interface()
        d_list = if_list_to_dict([i])
        if_list = dict_to_if_list(d_list)

    async def test_invalid_interface_name(self):
        test_passes = False
        try:
            await Interface("meow")
        except InterfaceNotFound:
            test_passes = True

        self.assertTrue(test_passes)

    async def test_nat_validation(self):
        nat = nat_info()
        i = Interface(nat=nat)
        i.set_nat(nat)

    async def test_fake_ext_route(self):
        one_valid = False
        for af in VALID_AFS:
            try:
                # Throws if no default route for AF.
                i = await Interface(af).start()

                # Throws if no NIC IP for AF.
                r = i.route(af)
                one_valid = True
            except Exception:
                continue

        self.assertTrue(one_valid)

    async def test_interface_start(self):
        start_worked = False
        i = await Interface()
        for af in i.supported():
            start_worked = True
            break

        self.assertTrue(start_worked)

    async def test_load_interfaces(self):
        if_names = await list_interfaces()
        ifs = await load_interfaces(if_names)
        self.assertTrue(len(ifs))

        # Check nic IP fetch. 
        i = ifs[0]
        af = i.supported()[0]
        n = i.nic(af)
        self.assertTrue(n is not None)

        # Check 'scope id' fetch (used for IPv6 bind code.)
        scope_id = i.get_scope_id()
        self.assertTrue(scope_id is not None)

        # Test loading NAT info for an interface.
        nat = await i.load_nat()
        self.assertTrue(nat is not None)

        # Test dict and load.
        x = eval(repr(i))
        self.assertTrue(isinstance(x, Interface))
        as_s = str(i)
        self.assertTrue(as_s in repr(i))

if __name__ == '__main__':

    main()