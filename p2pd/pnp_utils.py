import time
import struct
import os
from ecdsa import VerifyingKey
from .utils import *

DB_NAME = "pnp"
DB_USER = "root"
DB_PASS = os.environ['PNP_DB_PW']

#####################################################################################
PNP_PORT = 5300
PNP_NAME_LEN = 30 # 10
PNP_VAL_LEN = 135 
V4_NAME_LIMIT = 4
V6_NAME_LIMIT = 1
V6_GLOB_LIMIT = 3
V6_SUBNET_LIMIT = 15000
V6_IFACE_LIMIT = 10
MIN_NAME_DURATION = 60 * 60 * 24 * 7 # 7 days to migrate names.
BEHAVIOR_DO_BUMP = 1
BEHAVIOR_DONT_BUMP = 0

class PNPPacket():
    def __init__(self, name, value=b"", vkc=None, sig=None, updated=None, behavior=BEHAVIOR_DO_BUMP):
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

    def get_msg_to_sign(self):
        return PNPPacket(
            self.name,
            self.value,
            updated=self.updated,
            vkc=self.vkc,
            sig=None,
            behavior=self.behavior
        ).pack()

    def is_valid_sig(self):
        vk = VerifyingKey.from_string(self.vkc)
        msg = self.get_msg_to_sign()
        print("test sig msg = ")
        print(msg)
        try:
            # recover_verify_key(msg, self.sig, vk_b)
            vk.verify(self.sig, msg)
            return True
        except:
            log_exception()
            return False

    def pack(self):
        buf = b""

        # Behavior for changes.
        buf += bytes([self.behavior])

        # Prevent replay.
        buf += struct.pack("<Q", self.updated)
        assert(len(buf) == 9)

        # Header (lens.)
        buf += bytes([self.name_len])
        buf += bytes([self.value_len])

        # Body (var len - limit)
        buf += (self.name + (b"\0" * PNP_NAME_LEN))[:self.name_len]
        buf += (self.value + (b"\0" * PNP_VAL_LEN))[:self.value_len]
        
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

        # Extract behavior.
        behavior = buf[p]; p += 1;

        # Extract timestamp portion.
        updated = struct.unpack("<Q", buf[p:p + 8])[0]; p += 8;
        print("unpack updated = ")
        print(updated)

        # Extract header portion.
        name_len = min(buf[p], PNP_NAME_LEN); p += 1;
        val_len = min(buf[p], PNP_VAL_LEN); p += 1;

        # Extract body fields.
        name = buf[p:p + name_len]; p += name_len;
        val = buf[p:p + val_len]; p += val_len;

        # Extract sig field.
        vkc = buf[p:p + 25]; p += 25;
        sig = buf[p:]

        return PNPPacket(name, val, vkc, sig, updated, behavior)
