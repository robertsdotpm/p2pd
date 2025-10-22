import codecs
import hashlib

def sha256(msg       )         :
    return hashlib.sha256(msg).digest()


def decode_hex(s     )         :
    return codecs.decode(remove_0x(s), "hex")


# private below
def remove_0x(s     )       :
    if s.startswith("0x") or s.startswith("0X"):
        return s[2:]

    return s

