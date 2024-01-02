from p2pd.test_init import *
from p2pd import IP6, IP4, Route, Interface
from p2pd.net import AF_ANY, VALID_AFS, VALID_ANY_ADDR
from p2pd.errors import *
from p2pd.nat import nat_info
from p2pd.utils import what_exception
from p2pd.interface import load_interfaces, filter_trash_interfaces
from p2pd.interface import if_list_to_dict, dict_to_if_list

asyncio.set_event_loop_policy(SelectorEventPolicy())
class TestInterface(unittest.IsolatedAsyncioTestCase):
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