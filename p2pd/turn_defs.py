import socket
from struct import pack
import hmac
from hashlib import sha1
from .net import *
from .settings import *

# Config variables -------------------------------------

TURN_MAX_RETRANSMITS = 5
TURN_MAIN_REPLY_TIMEOUT = 5

# secs - Turn recommends 1 minute before expiry.
TURN_REFRESH_EXPIRY = 600 
TURN_MAX_DICT_LEN = 1000
TURN_MAX_RECV_PACKETS = 100

#########################################################
TURN_MAGIC_COOKIE = b"\x21\x12\xA4\x42"
TURN_MAGIC_XOR = b'\x00\x00\x21\x12\x21\x12\xa4\x42'
TURN_CHANNEL = b"\x40\x02\x00\x00"
TURN_PROTOCOL_TCP = b"\x06\x00\x00\x00"
TURN_RPOTOCOL_UDP = b"\x11\x00\x00\x00"
TURN_CHAN_RANGE = [16384, 32766]

# Protocol state machine.
# With convenient lookup values.
TURN_NOT_STARTED = 1
TURN_TRY_ALLOCATE = 2
TURN_ALLOCATE_FAILED = 3
TURN_TRY_REQ_TRANSPORT = 4
TURN_REQ_TRANSPORT_FAILED = 5
TURN_TRY_REFRESH = 6
TURN_REFRESH_DONE = 7
TURN_REFRESH_FAIL = 8
TURN_ERROR_STOPPED = 9

def turn_vars_to_server(var_list, af):
    return {
        "host": var_list[0],
        "port": var_list[1],
        "user": var_list[2],
        "pass": var_list[3],
        "realm": var_list[4]
    }
    
def find_turn_server(turn_server, turn_servers, af=None):
    for needle in turn_servers:
        # Not the same server host or IP.
        if needle["host"] != turn_server["host"]:
            continue

        # Not the same port.
        if needle["port"] != turn_server["port"]:
            continue

        # Not the same user.
        if needle["user"] != turn_server["user"]:
            continue

        # Not the same pass.
        if needle["pass"] != turn_server["pass"]:
            continue

        # Not the same realm.
        if needle["realm"] != turn_server["realm"]:
            continue

        # Not the same AF.
        if af is not None:
            if af not in needle["afs"]:
                continue

        return True

    return False