from p2pd import *
import time
from ecdsa import SigningKey

async def main():
    # wlx00c0cab5760d
    # enp0s25
    a = await Interface("enp0s25")
    #b = await Interface("enp0s25")

    input()

    #print(b.route(IP4))

    return



    TEST_SK = b'\xfe\xb1w~v\xfe\xc4:\x83\xa6C\x19\xde\x11\xc2\xc8\xc4A\xdaEC\x01\xc2\x9d'
    #sk = SigningKey.generate()
    #sk_string = sk.to_string()
    #print(sk_string)
    sk = SigningKey.from_string(TEST_SK)
    

    i = await Interface()
    print(i)
    return

    route = i.route(IP6)
    dest = await Address("2607:5300:0060:80b0:0000:0000:0000:0001", PNP_PORT, route)
    dest_pk = "03f20b5dcfa5d319635a34f18cb47b339c34f515515a5be733cd7a7f8494e97136"
    client = PNPClient(sk, dest, dest_pk)

    name = "my_test_name2"
    await client.push(name, "val")

    t1 = time.time()
    out = await client.fetch(name)
    print(out.value)
    assert(out.value == b"val")
    t2 = time.time()
    print(t2 - t1)

async_test(main)