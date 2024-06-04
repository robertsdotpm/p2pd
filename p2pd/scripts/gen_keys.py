from ecies.utils import generate_key
from ecies import encrypt, decrypt
secp_k = generate_key()
reply_sk = secp_k.secret
reply_pk = secp_k.public_key.format(True)


print(reply_pk)
print(len(reply_pk))

print(reply_sk)


x = decrypt(reply_sk, encrypt(reply_pk, b"test secret data"))
print(x)