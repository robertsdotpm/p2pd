"""
nc -4 -u p2pd.net 7

"""

from p2pd.test_init import *
try:
    from .static_route import *
except:
    from static_route import *
from p2pd.utils import what_exception, log_exception
from p2pd import IPRange, Bind, Route, Interface, pipe_open
from p2pd import Address
from p2pd.net import BLACK_HOLE_IPS, ip_norm, DUEL_STACK, IP6, IP4
from p2pd.net import NIC_BIND, EXT_BIND, VALID_AFS, TCP, UDP
from p2pd.base_stream import SUB_ALL

asyncio.set_event_loop_policy(SelectorEventPolicy())
class TestAFsWork(unittest.IsolatedAsyncioTestCase):
    async def test_afs(self):
        # Public IPs.
        # The BSD inetd seems broken for echo / udp / localhost bind.
        await init_p2pd()
        echo_ip = {
            IP4: P2PD_NET_V4_IP,
            IP6: P2PD_NET_V6_IP
        }

        one_worked = False
        for af in VALID_AFS:
            try:
                # Get default Interface for AF type.
                i = Interface(af)
                rp = use_fixed_rp(i)
                await i.start(rp)
                one_worked = True
            except Exception:
                # Skip test if not supported.
                continue

            # Echo server address.
            route = await i.route(af).bind()
            echo_dest = await Address(echo_ip[af], 7, route).res()

            # Test echo server with AF.
            msg = b"echo test\r\n"
            for proto in [TCP, UDP]:
                pipe = await pipe_open(proto, echo_dest, route)
                
                # Interested in any message.
                pipe.subscribe(SUB_ALL)

                # Send data down the pipe.
                await pipe.send(msg, echo_dest.tup)

                # Receive data back.
                data = await pipe.recv(SUB_ALL, 4)
                self.assertEqual(data, msg)

                # Test block match.
                await pipe.send(msg, echo_dest.tup)

                # Cleanup.
                await pipe.close()

        self.assertTrue(one_worked)

if __name__ == '__main__':
    main()