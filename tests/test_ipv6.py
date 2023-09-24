"""
nc -4 -u p2pd.net 7

"""

from p2pd.test_init import *
from p2pd.utils import log_exception, what_exception
from p2pd import STUNClient, Interface
from p2pd.net import VALID_AFS, TCP, UDP
from p2pd.base_stream import pipe_open, SUB_ALL, BaseProto
from p2pd.stun_client import tran_info_patterns, do_stun_request
from p2pd.stun_client import changeRequest, changePortRequest
from p2pd.ip_range import IPRange

class TestIPv6(unittest.IsolatedAsyncioTestCase):
    async def test_ipv6(self):
        """
        i = await Interface().start_local()
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

        i = Interface(stack=IP6)
        await i.start()

        print(i)



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

        dest = await Address("p2pd.net", 7, route)
        pipe = await pipe_open(TCP, route, dest)
        await pipe.send(b"Test")
        out = await pipe.recv()
        print(out)
        await pipe.close()
                

if __name__ == '__main__':
    main()