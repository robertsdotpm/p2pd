from p2pd import *

async def example():
    # Returns a list of Interface names.
    if_names = await list_interfaces()
    ifs = await load_interfaces(if_names)
    print(ifs)

if __name__ == '__main__':
    async_test(example)