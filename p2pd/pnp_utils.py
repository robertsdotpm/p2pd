import time
import random
import struct
from .ecies import generate_key
from ecdsa import VerifyingKey, SECP256k1
from .utils import *

#####################################################################################
PNP_PORT = 5300
PNP_NAME_LEN = 50 # 10
PNP_VAL_LEN = 500
V4_NAME_LIMIT = 10 #4
V6_NAME_LIMIT = 10 #1
V6_GLOB_LIMIT = 3
V6_SUBNET_LIMIT = 15000
V6_IFACE_LIMIT = 10
V6_ADDR_EXPIRY = 60 * 60 * 24 * 30 # 30 days no change expiry.
MIN_NAME_DURATION = 60 * 60 * 24 * 7 # 7 days to migrate names.
BEHAVIOR_DO_BUMP = 1
BEHAVIOR_DONT_BUMP = 0


class PNPPacket():
    def __init__(self, name, value=b"", vkc=None, sig=None, updated=None, behavior=BEHAVIOR_DO_BUMP, pkid=None, reply_pk=None, reply_sk=None):
        if updated is not None:
            self.updated = updated
        else:
            self.updated = int(time.time())

        self.name = to_b(name)
        self.name_len = min(len(self.name), PNP_NAME_LEN)
        self.value = to_b(value)
        self.value_len = min(len(self.value), PNP_VAL_LEN)
        self.vkc = vkc
        self.sig = sig
        self.behavior = behavior
        self.pkid = pkid or random.randrange(0, 2 ** 32)

        self.reply_pk = reply_pk
        self.reply_sk = reply_sk
        if vkc is not None:
            assert(len(vkc) == 33)

    def gen_reply_key(self):
        secp_k = generate_key()
        self.reply_sk = secp_k.secret
        self.reply_pk = secp_k.public_key.format(True)

    def get_msg_to_sign(self):
        return PNPPacket(
            self.name,
            self.value,
            updated=self.updated,
            vkc=self.vkc,
            sig=None,
            behavior=self.behavior,
            pkid=self.pkid,
            reply_pk=self.reply_pk,
        ).pack()

    def is_valid_sig(self):
        vk = VerifyingKey.from_string(self.vkc, curve=SECP256k1)
        msg = self.get_msg_to_sign()
        try:
            # recover_verify_key(msg, self.sig, vk_b)
            vk.verify(self.sig, msg)
            return True
        except:
            log_exception()
            return False

    def pack(self):
        buf = b""

        # ID for packet.
        buf += struct.pack("<I", self.pkid)
        assert(len(buf) == 4)

        # Reply pk.
        if self.reply_pk is not None:
            buf += self.reply_pk
            assert(len(self.reply_pk) == 33)
        else:
            buf += b"\0" * 33
        assert(len(buf) == 37)

        # Behavior for changes.
        buf += bytes([self.behavior])

        # `Pr`event replay.
        buf += struct.pack("<Q", self.updated)
        assert(len(buf) == 46)

        # Header (lens.)
        buf += bytes([self.name_len])
        buf += bytes([self.value_len])

        # Body (var len - limit)
        buf += (self.name + (b"\0" * PNP_NAME_LEN))[:PNP_NAME_LEN]
        buf += (self.value + (b"\0" * PNP_VAL_LEN))[:PNP_VAL_LEN]
        assert(len(buf) == 598)
        
        # Variable length.
        if self.vkc is not None:
            buf += self.vkc
        if self.sig is not None:
            buf += self.sig

        return buf
    
    @staticmethod
    def unpack(buf):
        # Point at start of buffer.
        p = 0

        # Packet ID.
        pkid = struct.unpack("<I", buf[p:p + 4])[0]; p += 4;

        # Reply pk.
        reply_pk = buf[p:p + 33]; p += 33;
        if not reply_pk:
            reply_pk = None

        # Extract behavior.
        behavior = buf[p]; p += 1;

        # Extract timestamp portion.
        updated = struct.unpack("<Q", buf[p:p + 8])[0]; p += 8;

        # Extract header portion.
        name_len = min(buf[p], PNP_NAME_LEN); p += 1;
        val_len = min(buf[p], PNP_VAL_LEN); p += 1;

        # Extract body fields.
        name = buf[p:p + name_len]; p += PNP_NAME_LEN;
        val = buf[p:p + val_len]; p += PNP_VAL_LEN;

        # Extract sig field.
        vkc = buf[p:p + 33]; p += 33;
        sig = buf[p:]

        return PNPPacket(name, val, vkc, sig, updated, behavior, pkid, reply_pk)

