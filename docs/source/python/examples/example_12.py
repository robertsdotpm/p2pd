from p2pd import *

async def example():
    i = await Interface().start()
    nat = await i.load_nat()
    #
    # Test echo server with AF.
    af = i.supported()[0]
    stun_servs = list_clone_rand(STUN_CHANGE_SERVERS[TCP][af], 1)
    stun_client = (await get_stun_clients(af, stun_servs, i, TCP))[0]
    wan_ip = await stun_client.get_wan_ip()
    ret = await stun_client.get_mapping(TCP)
    pipe = ret[-1]
    await pipe.close()

if __name__ == '__main__':
    async_test(example)