from p2pd import *

async def example():
    # Returns a list of Interface names.
    ifs = await load_interfaces()

if __name__ == '__main__':
    async_test(example)