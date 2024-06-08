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



- only one rule exc from change type


PLATFORM, NIC|EXT, AF, IP_TYPE (link local), normalisation, change, [BIND_IP, ip suffix "nic_no"],
PLAT, *, IP6, PRIVATE, [BIND_TUP, [3, 0]]
DEFAULT


... modify tup? 

else clause

"""

V6_VALID_ANY = ["*", "::", "::/0", "", "0000:0000:0000:0000:0000:0000:0000:0000"]
V6_VALID_LOCALHOST = ["localhost", "::1"]
V4_VALID_LOCALHOST = ["localhost", "127.0.0.1"]
VALID_LOCALHOST = ["localhost", "::1", "127.0.0.1"]
V4_VALID_ANY = ["*", "0.0.0.0", ""]
NIC_BIND = 1
EXT_BIND = 2
IP_PRIVATE = 3
IP_PUBLIC = 4
IP_APPEND = 5
IP_BIND_TUP = 6

class BindRule():
    def __init__(self, bind_rule):
        self.platform = bind_rule[0]
        self.af = bind_rule[1]
        self.type = bind_rule[2]
        self.hey = bind_rule[3]
        self.norm = bind_rule[4]
        self.change = bind_rule[5]

async def binder(af, interface=None, ip="", port=0, loop=None):
    # Table of edge-cases for bind() across platforms and AFs.
    bind_magic = [
        # Bypasses the need for interface details for localhost binds.
        ["*", VALID_AFS, IP_APPEND, VALID_LOCALHOST, "", ""],

        # No interface added to IP for V6 ANY.
        ["*", IP6, IP_APPEND, V6_VALID_ANY, "::", ""],

        # Make sure to normalize unusual bind all values for v4.
        ["*", IP4, IP_APPEND, V4_VALID_ANY, "0.0.0.0", ""],

        # Windows needs the nic no added to v6 private IPs.
        ["Windows", IP6, IP_APPEND, IP_PRIVATE, "", "nic_no"],

        # ... whereas other operating systems use the interface name.
        ["*", IP6, IP_APPEND, IP_PRIVATE, "", "name"],

        # Windows v6 bind any doesn't need scope ID.
        ["Windows", IP6, IP_BIND_TUP, V6_VALID_ANY, None, [3, 0]],

        # Localhost V6 bind tups don't need the scope ID.
        ["*", IP6, IP_BIND_TUP, V6_VALID_LOCALHOST, None, [3, 0]],

        # Other private v6 bind tups need the scope id in Windows.
        ["Windows", IP6, IP_BIND_TUP, IP_PRIVATE, None, [3, "nic_no"]],
    ]

    # Replace variable names with contents.
    def parse_change_val(var_str, interface):
        if var_str == "nic_no":
            return interface.nic_no
        if var_str == "name":
            return interface.name

    # Test whether bind rule matches.
    def test_bind_rule(ip, af, bind_rule, rule_type):
        bind_rule = BindRule(bind_rule)

        # Skip rule types we're not processing.
        if bind_rule.type != rule_type:
            return

        # Skip address types that don't apply to us.
        if type(bind_rule.af) == list:
            if af not in bind_rule.af:
                return
        else:
            if af != bind_rule.af:
                return

        # Skip platform rules that don't match us.
        if bind_rule.platform not in ["*", platform.system()]:
            return

        # Check hey for matches.
        if type(bind_rule.hey) == list:
            if ip not in bind_rule.hey:
                return
        if type(bind_rule.hey) == int:
            if bind_rule.hey == IP_PRIVATE:
                ipr = ip_f(ip)
                if not ipr.is_private:
                    return

        return bind_rule

    # Process bind rules.
    bind_tup = None
    for bind_rule in bind_magic:
        bind_rule = test_bind_rule(ip, af, bind_rule, IP_APPEND)
        if not bind_rule:
            continue

        # Do norm rule.
        if bind_rule.norm == "":
            ip = str(ip_f(ip))
        else:
            if bind_rule.norm is not None:
                ip = bind_rule.norm

        # Do logic specific to IP_APPEND.
        if bind_rule.change is not None:
            val = parse_change_val(bind_rule.change, interface)
            if val:
                ip += f"%{val}"
            else:
                ip += bind_rule.change

        # Only one rule ran per type.
        break

    # Lookup correct bind tuples to use.
    loop = loop or asyncio.get_event_loop()
    addr_infos = await loop.getaddrinfo(ip, port)
    if not len(addr_infos):
        raise Exception("Can't resolve IPv6 address for bind.")
    
    # Set initial bind tup.
    bind_tup = addr_infos[0][4]
        
    # Manipulate bind tuples if needed.
    for bind_rule in bind_magic:
        # Skip rule types we're not processing.
        bind_rule = test_bind_rule(ip, af, bind_rule, IP_BIND_TUP)
        if not bind_rule:
            continue

        # Apply changes to the bind tuple.
        offset, val_str = bind_rule.change
        val = parse_change_val(val_str, interface) or val_str
        bind_tup = list(bind_tup)
        bind_tup[offset] = val
        bind_tup = tuple(bind_tup)
            
        # Only one rule ran per type.
        break

    return bind_tup

class TestInterface(unittest.IsolatedAsyncioTestCase):
    async def test_fallback_zero_bind(self):
        ip = "::"
        port = 0
        af = IP6
        interface = None
        t = await binder(af, interface, ip, port)
        print(t)







        return
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