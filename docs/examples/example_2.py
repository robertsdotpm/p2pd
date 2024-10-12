from p2pd import *

async def example():
    # Start the default interface.
    nic = await Interface()
    
    # Load additional NAT details.
    # Restrict, random port NAT assumed by default.
    await nic.load_nat()
    
    # Show the interface details.
    print(nic)

if __name__ == '__main__':
    async_test(example)