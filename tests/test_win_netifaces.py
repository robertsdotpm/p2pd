import platform
from p2pd.test_init import *
from p2pd.utils import *
from p2pd.net import VALID_AFS
from p2pd.win_netifaces import *

if platform.system() == "Windows":
    class TestWinNetifaces(unittest.IsolatedAsyncioTestCase):
        async def test_get_interfaces(self):
            out = await get_ifaces()
            self.assertTrue(out != "")

        async def test_get_default_interface_by_if(self):
            found_one = False
            for af in VALID_AFS:
                out = await get_default_iface_by_af(af)
                if out is not None:
                    found_one = True
                    break

            self.assertTrue(found_one)

        async def test_extract_if_fields(self):
            out = await get_ifaces()
            results = extract_if_fields(out)
            self.assertTrue(len(results))

        async def test_get_addr_info_by_if_index(self):
            out = await get_ifaces()
            result = extract_if_fields(out)[0]
            out = await get_addr_info_by_if_index(result["no"])

            found_one = False
            for af in VALID_AFS:
                if len(out[af]):
                    found_one = True
                    break

            self.assertTrue(found_one)

        async def test_get_default_gw_by_if_index(self):
            out = await get_ifaces()
            result = extract_if_fields(out)[0]
            
            found_one = False
            for af in VALID_AFS:
                gw_info = await get_default_gw_by_if_index(af, result["no"])
                if gw_info is not None:
                    found_one = True
                    break

            self.assertTrue(found_one)

        async def test_win_load_interface_state(self):
            out = await get_ifaces()
            results = extract_if_fields(out)
            out = await win_load_interface_state(results)
            self.assertTrue(len(out))

            # Should find at least one default gateway.
            gws = win_set_gateways(out)
            self.assertTrue(gws["default"] != {})

        async def test_win_netifaces_class(self):
            n = await Netifaces().start()

            # Test gateways.
            gws = n.gateways()
            self.assertTrue(gws["default"] != {})

            # Test interface list.
            ifs = n.interfaces()
            self.assertTrue(len(ifs))
            if_name = ifs[0]

            # Test ifaddresses.
            if_addr = n.ifaddresses(if_name)
            self.assertTrue(len(if_addr[IP4]) + len(if_addr[IP6]))

            # Test nic no.
            if_index = n.nic_no(if_name)
            self.assertTrue(isinstance(if_index, int))

            # Test guid.
            guid = n.guid(if_name)
            self.assertTrue(len(guid))

    if __name__ == '__main__':
        main()
