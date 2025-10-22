import hashlib
import hmac
from .rc6 import RC6Encryption
from .hkdf import hkdf_expand

def sym_encrypt(key       , plain_text       )         :
    rc6 = RC6Encryption(key)
    iv, encrypted = rc6.data_encryption_CBC(plain_text)
    tag = hmac.new(key=iv + key, msg=encrypted, digestmod=hashlib.sha256).digest()
    assert(len(iv) == 16)
    assert(len(tag) == 32)

    cipher_text = bytearray()
    cipher_text.extend(iv) # 16

    cipher_text.extend(tag) # 16
    cipher_text.extend(encrypted)

    return bytes(cipher_text)

def sym_decrypt(key       , cipher_text       )         :
    iv = cipher_text[:16]
    tag = cipher_text[16:48]
    encrypted = cipher_text[48:]
    expected_tag = hmac.new(key=iv + key, msg=encrypted, digestmod=hashlib.sha256).digest()
    assert(tag == expected_tag)

    rc6 = RC6Encryption(key)
    plain_text = rc6.data_decryption_CBC(encrypted, iv)
    return plain_text

def derive_key(master       )         :
    derived = hkdf_expand(master, length=32, info=b"", hash=hashlib.sha256)

    return derived  # type: ignore

