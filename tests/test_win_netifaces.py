"""
            from p2pd.interface import Interface

            # 1.7 if real time is disabled and talking to a shell.

            loader = 'Invoke-Expression (Get-Content "~/net_info.ps1" -Raw)'


            # "Invoke-Expression (Read-Host)"
            p = subprocess.Popen(["powershell_ise.exe"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True                     
            )
            time.sleep(4)

            s1 = time.time()
            # 1 second just to start powershell with a loaded script.
            #await cmd("powershell echo test")
            #out = subprocess.run(["powershell.exe", "echo test"], stdout=asyncio.subprocess.PIPE)

            loader = 'Invoke-Expression (Get-Content "~/net_info.ps1" -Raw)'
            #loader = 'echo test'
            out, errs = p.communicate(input=loader)
            #p.stdin.write(f"{loader}\r\n")
            #out = p.stdout.read()
            param = powershell_encoded_cmd(loader)
            #out = subprocess.run(["powershell.exe", "-encodedCommand", param], stdout=asyncio.subprocess.PIPE)
            #out = subprocess.run(["powershell", loader], stdout=asyncio.subprocess.PIPE)

            "
            real time protect = 1 sec
            process start = 1 sec

            a power shell server would shave 2 secs off
            you could also make it cache results
            script = 1 sec
            "

            #out = subprocess.run(["powershell.exe", "-encodedCommand", powershell_encoded_cmd(IFS_PS1)], stdout=asyncio.subprocess.PIPE)
            #i = await init_p2pd()

            "
            out = await (
                "powershell.exe",
                ("echo test")
            )
            "

            s2 = time.time()
            t = s2 - s1
            print(t)
            print(out)
            #print(errs)
            return

            i = await init_p2pd()
            print(i)
            
            return

caching + look to see if anything changed in the guid reg keys to trigger new load
is prob the way to go

todo: dont use the commandencoded trick
    -- write the script to user profile
    -- and use the loader function
"""

import platform
from p2pd import *


if platform.system() == "Windows":
    class TestWinNetifaces(unittest.IsolatedAsyncioTestCase):
        
        async def test_win_netifaces_ps(self):
            try:
                # test_get_interfaces(self):
                out = await get_ifaces()
                self.assertTrue(out != "")

                #test_get_default_interface_by_if(self):
                found_one = False
                for af in VALID_AFS:
                    out = await get_default_iface_by_af(af)
                    if out is not None:
                        found_one = True
                        break

                self.assertTrue(found_one)

                # async def test_extract_if_fields(self):
                out = await get_ifaces()
                results = extract_if_fields(out)
                self.assertTrue(len(results))

                # async def test_get_addr_info_by_if_index(self):
                out = await get_ifaces()
                result = extract_if_fields(out)[0]
                out = await get_addr_info_by_if_index(result["no"])

                found_one = False
                for af in VALID_AFS:
                    if len(out[af]):
                        found_one = True
                        break

                self.assertTrue(found_one)

                # async def test_get_default_gw_by_if_index(self):
                out = await get_ifaces()
                result = extract_if_fields(out)[0]
                
                found_one = False
                for af in VALID_AFS:
                    gw_info = await get_default_gw_by_if_index(af, result["no"])
                    if gw_info is not None:
                        found_one = True
                        break

                self.assertTrue(found_one)

                # async def test_win_load_interface_state(self):
                out = await get_ifaces()
                results = extract_if_fields(out)
                out = await win_load_interface_state(results)
                self.assertTrue(len(out))

                # Should find at least one default gateway.
                gws = win_set_gateways(out)
                self.assertTrue(gws["default"] != {})
            except:
                log("test win ifaces failed using powershell code. Possible failure.")
                log_exception()

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
