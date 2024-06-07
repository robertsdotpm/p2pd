from p2pd import to_h
from p2pd.ecies.utils import generate_key
secp_k = generate_key()
reply_sk = secp_k.secret
reply_pk = secp_k.public_key.format(True)

reply_pk_hex = to_h(reply_pk)
reply_sk_hex = to_h(reply_sk)

print(f"reply pk hex = {reply_pk_hex}")
print(f"reply sk hex = {reply_sk_hex}")