from p2pd import *

async def example():
    # Returns a list of Interface objects for Inter/networking.
    netifaces = await init_p2pd()
    ifs = await load_interfaces(netifaces=netifaces)

if __name__ == '__main__':
    async_test(example)