from p2pd import *

async def example():
    # Start the default interface.
    i = await Interface()
    #
    # Load additional NAT details.
    # Restrict, random port NAT assumed by default.
    await i.load_nat()
    #
    # Show the interface details.
    repr(i)

if __name__ == '__main__':
    async_test(example)