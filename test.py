from p2pd import *
import time
from ecdsa import SigningKey, SECP256k1, ECDH

async def main():
    nic = await Interface()
    s = STUNClient(IP6, ("2600:1f16:8c5:101:80b:b58b:828:8df4", 3478), nic, proto=TCP)
    out = await s.get_mapping()
    print(out)
    return

    sk = SigningKey.generate(curve=SECP256k1)
    print(sk)

    ecdh_alice = ECDH(curve=SECP256k1)
    ecdh_alice.generate_private_key()

    sk_bob = SigningKey.generate(curve=SECP256k1)
    bob_pub = sk_bob.get_verifying_key()

    ecdh_alice.load_received_public_key(bob_pub)
    

    secret = ecdh_alice.generate_sharedsecret_bytes()
    print(secret)


    return
    # wlx00c0cab5760d
    # enp0s25
    a = await Interface("Intel(R) 82574L Gigabit Network Connection")
    
    print(a)
    return
    #b = await Interface("enp0s25")

    input()

    #print(b.route(IP4))

    return






async_test(main)