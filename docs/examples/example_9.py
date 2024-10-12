
from p2pd import *

async def example():
    serv = Daemon()
    nic = await Interface()
    af = nic.supported()[0]
    route = await nic.route(af).bind()
    await serv.add_listener(
        TCP,
        route,
    )
    
    await serv.close()

if __name__ == '__main__':
    async_test(example)