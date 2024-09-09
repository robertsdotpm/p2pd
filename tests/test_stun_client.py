"""
nc -4 -u p2pd.net 7

"""


try:
    from .static_route import *
except:
    from static_route import *
import os
from p2pd import *


env = os.environ.copy()
class TestStunClient(unittest.IsolatedAsyncioTestCase):
    async def test_stun_client(self):
        i = await Interface()
        print(i)
    
        dest = ("3.132.228.249", 3478)
        s = STUNClient(IP4, dest, i)
        _, _, p = await s.get_mapping()
    

        ctup = ("3.135.212.85", 3479)
        #out = await s.get_change_port_reply(ctup, p)
        #print(out)

        out = await s.get_change_tup_reply(ctup)
        print(out)

if __name__ == '__main__':
    main()