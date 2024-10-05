from p2pd import *

TURN_OFFSET = 0

async def example():


    # Network interface details.
    nic = await Interface()
    client = await TURNClient(IP4, dest, nic, auth)
    print(client)

    our_relay_tup = await client.relay_tup_future
    our_client_tup = await client.client_tup_future
    print(our_relay_tup, our_client_tup)

    await client.close()



if __name__ == '__main__':
    async_test(example)