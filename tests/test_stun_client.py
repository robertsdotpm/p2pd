"""
nc -4 -u p2pd.net 7

"""

from p2pd.test_init import *
try:
    from .static_route import *
except:
    from static_route import *
import os
from p2pd.utils import log_exception, what_exception
from p2pd import STUNClient, Interface
from p2pd.settings import *
from p2pd.net import VALID_AFS, TCP, UDP
from p2pd.nat import *
from p2pd.base_stream import pipe_open, SUB_ALL, BaseProto
from p2pd.stun_client import tran_info_patterns, do_stun_request
from p2pd.stun_client import changeRequest, changePortRequest
from p2pd.ip_range import IPRange

env = os.environ.copy()
class TestStunClient(unittest.IsolatedAsyncioTestCase):
    async def test_stun_client(self):
        one_valid = False
        for af in VALID_AFS:
            try:
                # Get default Interface for AF type.
                i = Interface(af)
                #rp = use_fixed_rp(i)
                await i.start()
                one_valid = True
            except Exception:
                # Skip test if not supported.
                continue

            # Test echo server with AF.
            stun_client = STUNClient(i, af)
            wan_ip = await stun_client.get_wan_ip()
            self.assertTrue(wan_ip)

            m = await stun_client.get_mapping(proto=TCP) 
            self.assertTrue(isinstance(m[0], Interface)) # Interface used for stun.
            self.assertTrue(isinstance(m[1], BaseProto))  # Instance of open socket to stun server.
            self.assertTrue(isinstance(m[2], int)) # Local port
            self.assertTrue(isinstance(m[3], int)) # Remote mapping
            self.assertTrue(isinstance(m[4], str)) # Remote IP
            self.assertTrue(m[2]) # Local port
            self.assertTrue(m[3]) # Mapped port
            IPRange(m[4]) # Is valid IP

            # Stun server addr.
            route = await i.route(af).bind()
            stun_server = STUNT_SERVERS[af][0]
            dest = await Address(
                stun_server["primary"]["ip"],
                stun_server["primary"]["port"],
                route,
                UDP
            ).res()

            # Check NAT test result is as expected.
            # Then check that other STUN requests work.
            if env.get("NAT_OPEN_INTERNET", False):
                nat_type = await stun_client.get_nat_type()
                if nat_type not in [OPEN_INTERNET, SYMMETRIC_UDP_FIREWALL]:
                    continue

                for req in [changeRequest, changePortRequest]:
                    # Test change port request.
                    pipe = (await pipe_open(
                        UDP,
                        route,
                        dest
                    )).subscribe(SUB_ALL)

                    # Used for matching the TXID for the stun reply.
                    tran_info = tran_info_patterns(dest.tup)
                    tran_info[1] = 0 # Match any host tuple.
                    extra_data = req
                    pipe.subscribe(tran_info[:2])

                    # Do the change request.
                    ret = await do_stun_request(pipe, dest, tran_info, extra_data=extra_data)
                    if nat_type == OPEN_INTERNET:
                        self.assertTrue(ret["resp"])
                    await pipe.close()

        self.assertTrue(one_valid)
                

if __name__ == '__main__':
    main()