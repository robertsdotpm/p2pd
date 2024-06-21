from p2pd import *

servers = [


]

u = []
[u.append(i) for i in servers if i not in u]
servers = u


async def main(servers):
    i = await Interface()
    loop = asyncio.get_event_loop()

    #servers = [["jump.chat", 3478]]
    #servers = [["webrtc.free-solutions.org", 3478], ]

    """
    v6 = []
    for server in servers:
        server = [server["host"], server["port"]]
        x = await loop.getaddrinfo(host=server[0], port=server[1])
        for d in x:
            if d[0] == IP6:
                v6.append(server)

    print(v6)

    return
    """

    # Open servers list and skip done results.
    sfp = open("servers.txt", "r")
    got = eval("[" + sfp.read() + "]")
    print(f"Skipping {len(got)} servers already processed.")
    x = [s for s in servers if s not in got]
    servers = x
    sfp.close()
    sfp = open("servers.txt", "a")

    # Open filtered results.
    tfp = open("tcp.txt", "a")
    ufp = open("udp.txt", "a")
    for server in servers:
        print(f"trying {server}")
        async def worker():
            # UDP must be used for NAT test.
            s = STUNClient(interface=i)
            s.proto = UDP
            nat_type = await s.get_nat_type(servers=[server])
            if nat_type == 3:
                ufp.write(f"{server}\r\n")
                print(f"udp {server}")

            # We also need a server that supports TCP.
            # TCP is needed for the mapping test.
            s.proto = TCP
            m = await s.get_mapping(servers=[server], proto=TCP)
            if m[2] is not None:
                tfp.write(f"{server}\r\n")
                print(f"tcp {server}")

            return None

        sfp.write(f"{server},\r\n")
        await worker()
        #break

    sfp.close()
    tfp.close()
    ufp.close()

async_test(main, args=[servers])