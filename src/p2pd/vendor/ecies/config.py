COMPRESSED_PUBLIC_KEY_SIZE = 33
UNCOMPRESSED_PUBLIC_KEY_SIZE = 65


class Config:
    def __init__(self):
        self.is_ephemeral_key_compressed = False
        self.is_hkdf_key_compressed = False

    def ephemeral_key_size(self):
        if self.is_ephemeral_key_compressed:
            return COMPRESSED_PUBLIC_KEY_SIZE
        else:
            return UNCOMPRESSED_PUBLIC_KEY_SIZE

ECIES_CONFIG = Config()
