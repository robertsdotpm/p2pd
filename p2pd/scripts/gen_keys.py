from ecies.utils import generate_eth_key, generate_key
eth_k = generate_eth_key()
sk_hex = eth_k.to_hex()  # hex string
pk_hex = eth_k.public_key.to_hex()  # hex string

print(f"Pub key = {pk_hex}")
print(f"Priv key = {sk_hex}")