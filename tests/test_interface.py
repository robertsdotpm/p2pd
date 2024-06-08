from p2pd import *

"""

nic_bind, ext_bind

bind:
    convert ips:
        interface (assumes resolved)

"", localhost, ::1
*, ::, ::/0, 0.0.0.0

flag loopback:
    [:2]

V6_VALID_ANY = ["*", "::", "::/0", ""]
V6_VALID_LOCALHOST = ["localhost", "::1"]
V4_VALID_LOCALHOST = ["localhost", "127.0.0.1"]
V4_VALID_ANY = ["*", "0.0.0.0", ""]
NIC_BIND = 1
EXT_BIND = 2
IP_PRIVATE = 3
IP_PUBLIC = 4
IP_APPEND = 5
IP_BIND_TUP = 6

bind_magic = [
    # No interface added to IP for V6 ANY.
    ["*", IP6, IP_APPEND, V6_VALID_ANY, "::", ""],

    # Windows needs the nic no added to v6 private IPs.
    ["Windows", IP6, IP_APPEND, IP_PRIVATE, "", "nic_no"],

    # Whereas other operating systems use the interface name,
    ["*", IP6, IP_APPEND, IP_PRIVATE, "", "name"],

    # Localhost V6 bind tups don't need the scope ID.
    ["*", IP6, IP_BIND_TUP, V6_VALID_LOCALHOST, "::1", [3, 0]],

    # Other private v6 bind tups need the scope id in Windows.
    ["Windows", IP6, IP_BIND_TUP, IP_PRIVATE, None, [3, "nic_no"]],

    # Make sure to normalize unusual bind all values for v4.
    ["*", IP4, IP_APPEND, V4_VALID_ANY, "0.0.0.0", ""],
]


- only one rule exc from change type


PLATFORM, NIC|EXT, AF, IP_TYPE (link local), normalisation, change, [BIND_IP, ip suffix "nic_no"],
PLAT, *, IP6, PRIVATE, [BIND_TUP, [3, 0]]
DEFAULT


... modify tup? 

else clause

"""



class TestInterface(unittest.IsolatedAsyncioTestCase):
    async def test_fallback_zero_bind(self):
        i = await Interface().start_local()
        af = IP6
        local_addr = await Bind(
            i,
            af=af,
            port=0,
            ips=ANY_ADDR_LOOKUP[af]
        ).res()


        # '::', p, 0, 0 for ipv6
        # '0.0.0.0' p for ipv4
        # Listen all prob isnt properly tested then.
        # Returning tups directly for any might make sense.
        t = local_addr._bind_tups[1][:-1] + (0,)
        local_addr._bind_tups[1] = t
        local_addr._bind_tups[2] = t
        print(local_addr._bind_tups)


        stun_client = STUNClient(i, af)
        wan_ip = await stun_client.get_wan_ip(
            local_addr=local_addr
        )
        print(wan_ip)

    # Should find at least a valid iface on whatever OS.
    async def test_default_interface(self):
        i = await Interface().start_local()
        self.assertTrue(i.name)

        i = await Interface("").start_local()
        self.assertTrue(i.name)

        i = await Interface(AF_ANY).start_local()
        self.assertTrue(i.name)

        i = await Interface().start_local()
        d_list = if_list_to_dict([i])
        if_list = dict_to_if_list(d_list)

    async def test_invalid_interface_name(self):
        test_passes = False
        try:
            await Interface("meow").start_local()
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

    async def test_win_netifaces_bypass(self):
        pass

    async def test_interface_start(self):
        start_worked = False
        for af in VALID_AFS:
            try:
                await Interface(af).start()
                start_worked = True
                break
            except Exception:
                pass

        self.assertTrue(start_worked)

    async def test_load_interfaces(self):
        ifs = await load_interfaces()
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