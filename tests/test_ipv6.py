"""
nc -4 -u p2pd.net 7

"""

from p2pd import *


class TestIPv6(unittest.IsolatedAsyncioTestCase):
    async def test_ipv6(self):
        """
        i = await Interface()
        s = STUNClient(interface=i, proto=UDP, af=IP6)
        x = await s.get_wan_ip()
        print(x)
        """

        netifaces = await init_p2pd()
        i_name = netifaces.interfaces()[0]
        addr_info = netifaces.ifaddresses(i_name)
 
        servers = [
            {
                "host": "p2pd.net",
                "primary": {"ip": "2a01:4f9:3081:50d9::2", "port": 3478},
                "secondary": {"ip": "2a01:4f9:3081:50d9::3", "port": 3479},
            },

        ]

        i = Interface()
        await i.start()

        print(i)
        return



        s = STUNClient(interface=i, proto=UDP, af=IP6)
        x = await s.get_wan_ip(servers=servers)
        print("wan ip == ")
        print(x)
        return




        ipr_nic = IPRange("fe80::f75c:ff8e:b0dd:2ce2")
        ipr_ext = IPRange("2403:5800:b018:8000::4a0d")
        route = Route(
            IP6,
            nic_ips=[ipr_nic],
            ext_ips=[ipr_ext],
            interface=i
        )

        await route

        dest = ("p2pd.net", 7)
        pipe = await pipe_open(TCP, dest, route)
        await pipe.send(b"Test")
        out = await pipe.recv()
        print(out)
        await pipe.close()
                

if __name__ == '__main__':
    main()