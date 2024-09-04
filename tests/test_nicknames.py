"""

async def test_nicknames():
    node = await get_node()
    print(node)
    print(node.sk)

    nic = node.ifs[0]


    name = ""
    val = "unique test val2"


    n = Naming(node.sk, nic)
    await n.start()

    print(n.clients[0].dest.af)

    out = await n.clients[0].push(name, val)
    print(out)
    print(out.value)
    return

    name = await n.push(name, val)
    print(name)


    out = await n.fetch(name)
    print(out)

    await n.delete(name)

    out = await n.fetch(name)
    print(out)




    name = "test name 33600"
    val = name
    af = IP6
    serv = PNP_SERVERS[af][1]
    nic = await Interface("wlx00c0cab5760d")
    dest = await Address(
        serv["ip"],
        serv["port"],
        nic.route(af)
    )

    print(dest.tup)

    pnpc = PNPClient(node.sk, dest, h_to_b(serv["pk"]))

    out = await pnpc.push(name, val)


    out = await pnpc.fetch(name)
    print(out)
    print(out.value)

    print(pnpc)


    await node.close()

    # 24 random bytes.
    # SigningKey.from_string(h_to_b(sk_hex))

"""

