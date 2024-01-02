from p2pd import *

async def example():
    # Returns a list of Interface objects for Inter/networking.
    ifs = await load_interfaces()

if __name__ == '__main__':
    async_test(example)