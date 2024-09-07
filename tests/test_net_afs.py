"""
nc -4 -u p2pd.net 7

"""


try:
    from .static_route import *
except:
    from static_route import *
from p2pd import *


class TestAFsWork(unittest.IsolatedAsyncioTestCase):
    async def test_afs(self):
        # List of public echo servers.
        addr = {
            UDP: {
                IP4: {
                    "host": "52.43.121.77",
                    "port": 10001
                },
                # TODO: Find IPv6 UDP public echo server.
            },
            TCP: {
                IP4: {
                    "host": "tcpbin.com",
                    "port": 4242
                },
                IP6: {
                    "host": "p2pd.net",
                    "port": 7
                }
            }
        }

        # Test all available AFs + protos.
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

            pipe = None
            try:
                # Echo server address.
                route = await i.route(af).bind()

                # Test echo server with AF.
                msg = b"echo test"
                for proto in [TCP, UDP]:
                    # No server for this AF + proto.
                    if af not in addr[proto]:
                        continue

                    # Set destination of echo server.
                    echo_dest = (
                        addr[proto][af]["host"],
                        addr[proto][af]["port"]
                    )

                    # Open pipe to echo server.
                    pipe = await pipe_open(proto, echo_dest, route)
                    
                    # Interested in any message.
                    pipe.subscribe(SUB_ALL)

                    # Send data down the pipe.
                    for i in range(0, 4):
                        await pipe.send(msg + b"\r\n", echo_dest.tup)

                    # Receive data back.
                    data = await pipe.recv(SUB_ALL, 4)
                    assert(msg in data)

                    # Cleanup.
                    await pipe.close()
                    pipe = None
            except:
                log_exception()
            finally:
                if pipe is not None:
                    await pipe.close()

        self.assertTrue(one_worked)
        await asyncio.sleep(2)

if __name__ == '__main__':
    main()