from p2pd import *

async def example():
    n = await init_p2pd()
    i = await Interface(netifaces=n).start()
    nat = await i.load_nat()
    #
    # Test echo server with AF.
    stun_client = STUNClient(i, i.supported()[0])
    wan_ip = await stun_client.get_wan_ip()
    results = await stun_client.get_mapping(TCP)

if __name__ == '__main__':
    async_test(example)