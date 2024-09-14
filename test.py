from p2pd import *
import time
from ecdsa import SigningKey, SECP256k1, ECDH

async def main():

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