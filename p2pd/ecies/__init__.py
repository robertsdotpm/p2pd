from ecdsa import SECP256k1, ECDH, SigningKey

from .utils import (
    sym_decrypt,
    sym_encrypt,
)

__all__ = ["encrypt", "decrypt", "ECIES_CONFIG"]

# Bytes: receiver_pk, Bytes: msg
def encrypt(receiver_pk, msg):
    # Generate unique per message key.
    ephemeral_keys = ECDH(curve=SECP256k1)
    ephemeral_keys.generate_private_key()

    # Get a reference to its public key.
    ephemeral_pk = ephemeral_keys.get_public_key()
    ephemeral_pk = ephemeral_pk.to_string("compressed")

    # Combine it with a fixed pub key for the other side.
    # This yields a shared secret for use with symmetric encryption.
    ephemeral_keys.load_received_public_key_bytes(receiver_pk)
    sym_key = ephemeral_keys.generate_sharedsecret_bytes()

    # Now encrypt the message with that shared secret as the key.
    encrypted = sym_encrypt(sym_key, msg)

    # Return the per message pub key and the encrypted output.
    # The ephemeral pk is 33 bytes.
    return ephemeral_pk + encrypted

# SigningKey: receiver_sk, bytes: msg
def decrypt(receiver_sk, msg):
    # Generate unique per message key.
    ephemeral_keys = ECDH(curve=SECP256k1)
    ephemeral_keys.load_private_key(receiver_sk)

    ephemeral_pk = msg[0:33]
    encrypted = msg[33:]

    ephemeral_keys.load_received_public_key_bytes(ephemeral_pk)
    secret = ephemeral_keys.generate_sharedsecret_bytes()

    return sym_decrypt(secret, encrypted)


"""
sk_bob = SigningKey.generate(curve=SECP256k1)
bob_pub = sk_bob.get_verifying_key().to_string("compressed")

msg = b"original message"
out = encrypt(bob_pub, msg)
print(out)

out = decrypt(sk_bob, out)
print(out)
"""