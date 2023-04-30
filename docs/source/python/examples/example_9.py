
from p2pd import *

async def example():
    p = 10233
    d = Daemon()
    n = await init_p2pd()
    i = await Interface(netifaces=n).start()
    b = await i.route(i.supported()[0]).bind(ips="127.0.0.1")
    await d.listen_specific(
        targets=[[b, TCP]],
    )
    #
    await d.close()

if __name__ == '__main__':
    async_test(example)