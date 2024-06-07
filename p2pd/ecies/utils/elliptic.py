from coincurve import PrivateKey, PublicKey
from coincurve.utils import get_valid_secret
from ..config import ECIES_CONFIG
from .hex import decode_hex
from .symmetric import derive_key


def generate_key()              :
    return PrivateKey(get_valid_secret())

def hex2pk(pk_hex     )             :
    uncompressed = decode_hex(pk_hex)
    if len(uncompressed) == 64:  # eth public key format
        uncompressed = b"\x04" + uncompressed

    return PublicKey(uncompressed)

def hex2sk(sk_hex     )              :
    return PrivateKey(decode_hex(sk_hex))

# private below
def encapsulate(private_key            , peer_public_key           )         :
    is_compressed = ECIES_CONFIG.is_hkdf_key_compressed
    shared_point = peer_public_key.multiply(private_key.secret)
    master = private_key.public_key.format(is_compressed) + shared_point.format(
        is_compressed
    )

    return derive_key(master)

def decapsulate(public_key           , peer_private_key            )         :
    is_compressed = ECIES_CONFIG.is_hkdf_key_compressed
    shared_point = public_key.multiply(peer_private_key.secret)
    master = public_key.format(is_compressed) + shared_point.format(is_compressed)

    
    return derive_key(master)

