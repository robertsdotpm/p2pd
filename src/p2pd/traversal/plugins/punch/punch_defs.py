from ....net.net_defs import *

# Punch modes.
TCP_PUNCH_LAN = 1
TCP_PUNCH_REMOTE = 2
TCP_PUNCH_SELF = 3

PUNCH_ALIVE = b"234o2jdjf\n"
PUNCH_END = b"qwekl2k343ok\n"
INITIATED_PREDICTIONS = 1
RECEIVED_PREDICTIONS = 2
UPDATED_PREDICTIONS = 3
INITIATOR = 1
RECIPIENT = 2

# Number of seconds in the future from an NTP time
# for hole punching to occur.
NTP_MEET_STEP = 6

# Fine tune various network settings.
PUNCH_CONF = dict_child({
    # Reuse address tuple for bind() socket call.
    "reuse_addr": True,

    # Return the sock instead of the base proto.
    #"sock_only": True,

    # Disable closing sock on error
    # Applies to the pipe_open only (may not be needed.)
    "do_close": False,
}, NET_CONF)


class PortAlloc():
    def __init__(self, src_port, dest_port):
        self.src_port = src_port
        self.dest_port = dest_port

    def __iter__(self):
        yield self.src_port
        yield self.dest_port

