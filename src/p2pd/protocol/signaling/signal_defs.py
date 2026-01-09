from aionetiface import *

MQTT_CONF = dict_child({
    "con_timeout": 4,
    "recv_timeout": 4
}, NET_CONF)

SIG_CON = 1
SIG_TCP_PUNCH = 2
SIG_TURN = 3
SIG_GET_ADDR = 4
SIG_RETURN_ADDR = 5
SIG_DONE = 6
SIG_RETRY = 7
P2P_PIPE_CONF = {
    "addr_families": [IP4, IP6],
    "addr_types": [EXT_BIND, NIC_BIND],
    "return_msg": False,
}

P2P_DIRECT = 1
P2P_REVERSE = 2
P2P_PUNCH = 3
P2P_RELAY = 4


DIRECT_FAIL = 11
REVERSE_FAIL = 12
PUNCH_FAIL = 13
RELAY_FAIL = 14

# TURN is not included as a default strategy because it uses UDP.
# It will need a special explanation for the developer.
# SOCKS might be a better protocol for relaying in the future.
P2P_STRATEGIES = [P2P_DIRECT, P2P_REVERSE, P2P_PUNCH]

