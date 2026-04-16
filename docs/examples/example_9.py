
from p2pd import *

async def example():
    nic = await Interface()
    af = nic.supported()[0]
    route = await nic.route(af).bind()
    async with Daemon() as serv:
        await serv.add_listener(TCP, route)

if __name__ == '__main__':
    async_test(example)