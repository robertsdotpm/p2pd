
from p2pd import *

async def example():
    p = 10233
    d = Daemon()
    i = await Interface().start()
    b = await i.route(i.supported()[0]).bind(ips="127.0.0.1")
    await d.add_listener(
        TCP,
        b,
    )
    
    await d.close()

if __name__ == '__main__':
    async_test(example)