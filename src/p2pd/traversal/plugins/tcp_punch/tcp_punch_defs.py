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
