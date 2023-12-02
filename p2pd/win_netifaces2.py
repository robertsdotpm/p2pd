r"""
    "guid": guid,
    "name": if_desc,
    "no": if_index,
    "mac": mac_addr,

    # Placeholders.
    "addr": None,
    "gws": { IP4: None, IP6: None },
    "defaults": None

    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\
        ... guid
            DhcpDefaultGateway
            DhcpIPAddress
            DhcpSubnetMask
            EnableDHCP (what params for static?)
    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{1c76ee53-53d3-4b5a-9632-0af0da012906}
        .. guid
            EnableDHCP
            Dhcpv6IanaAddr

            hardware address?
            link local address?
            no?

    Names here:
        HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards

    Computer\HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000
    Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0014
        net luid index 8004
        net luid
        NdisIfGetInterfaceIndexFromNetLuid


    reg_keys = {
        IP4: [
            ""
        ],
        IP6: [
            ""
        ]
    }

    PCI\VEN_8086&DEV_51F1&SUBSYS_40908086&REV_01\3&11583659&0&A3

    Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\PCI\VEN_8086&DEV_51F1&SUBSYS_40908086&REV_01\3&11583659&0&A3
        for all pcis ...
            filter non network
            ... calculate rank
            sort by rank
            assign offset based on position in array

    Computer\HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}
        this has all the guid for the network devices

        Computer\HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\...
            luid index
            device instance id
            component id
            if type 6
            
"""

import re
import winreg

def win_pci_to_ifindex():
    net_class_guids = [
        # Network.
        "{4d36e972-e325-11ce-bfc1-08002be10318}",

        # Bluetooth.
        "{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}"
    ]

    pci_path = r'SYSTEM\CurrentControlSet\Enum\PCI'
    root_reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
    pci_root = winreg.OpenKey(root_reg, pci_path, 0, winreg.KEY_READ)
    print(pci_root)
    print(winreg.QueryInfoKey(pci_root)[0])
    pci_no = winreg.QueryInfoKey(pci_root)[0]

    pci_table = []
    for i in range(pci_no):
        pci_key_name = winreg.EnumKey(pci_root, i)
        pci_device_root = winreg.OpenKey(pci_root, pci_key_name, 0, winreg.KEY_READ)
        pci_device_sub_name = winreg.EnumKey(pci_device_root, 0)
        pci_device_sub = winreg.OpenKey(
            pci_device_root,
            pci_device_sub_name,
            0,
            winreg.KEY_READ
        )


        try:
            friendly_name = winreg.QueryValueEx(pci_device_sub, "FriendlyName")[0]
        except:
            friendly_name = ""

        guid = winreg.QueryValueEx(pci_device_sub, "ClassGUID")[0]
        print(guid)
        if guid not in net_class_guids:
            #continue
            pass

        location_info = winreg.QueryValueEx(pci_device_sub, "LocationInformation")[0]
        magic_tup = re.findall("[(]([0-9]+),([0-9]+),([0-9]+)[)]$", location_info)[0]
        print(magic_tup)

        pci_no, device_no, func_no = [int(x) for x in magic_tup]
        ranking = (pci_no * 10) + func_no + device_no
        pci_table.append({
            "friendly_name": friendly_name,
            "ranking": ranking,
            "device_no": device_no,
            "guid": guid,
            "pci": f"{pci_key_name}\{pci_device_sub_name}",
            "ifindex": None
        })

    # Sort PCI table by ranking.
    pci_table = sorted(pci_table, key=lambda d: d['ranking']) #  reverse=True

    # Calculate the ifindexes.
    for ifindex, pci_entry in enumerate(pci_table):
        pci_entry["ifindex"] = ifindex + 1


    print(pci_table)


win_pci_to_ifindex()

r"""


aReg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
print(r"*** Reading from %s ***" % aKey)

aKey = winreg.OpenKey(aReg, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
for i in range(1024):
    try:
        aValue_name = winreg.EnumKey(aKey, i)
        oKey = winreg.OpenKey(aKey, aValue_name)
        sValue = winreg.QueryValueEx(oKey, "DisplayName")
        print(sValue)
    except EnvironmentError:
        break
"""