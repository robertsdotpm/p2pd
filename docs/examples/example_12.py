from p2pd import *

# NOTE: Servers may change IPs!
# Try use IP4 for af with another IP if it doesn't work.
async def example():
    # Load default interface.
    nic = await Interface()
    dest = ("stun.hot-chilli.net", 3478)

    # Use the first address family support for your NIC.
    af = nic.supported()[0]

    # Load STUN client.
    client = STUNClient(af, dest, nic, proto=UDP, mode=RFC3489)

    # Make some BIND requests.
    wan_ip = await client.get_wan_ip()
    ret = await client.get_mapping()
    print(wan_ip)
    print(ret)

if __name__ == '__main__':
    async_test(example)