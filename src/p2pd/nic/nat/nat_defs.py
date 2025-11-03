STUN_PORT = 3478
MAX_MAP_NO = 100
USE_MAP_NO = 2

# NAT TYPES ---------------------------------------------

# No NAT at all.
OPEN_INTERNET = 1

# There is no NAT but there is some kind of firewall.
SYMMETRIC_UDP_FIREWALL = 2

# Mappings are made for local endpoints.
# Then any destination can use the mapping to reach the local enpoint.
# Note: May be incorrectly detected if using TCP.
FULL_CONE = 3

# NAT reuses mapping if same src ip and port is used.
# Destination must be white listed. It can use any port to send replies on.
# Endpoint-independent
# Note: May be incorrectly detected if using TCP.
RESTRICT_NAT = 4

# Mappings reused based on src ip and port.
# Destination must be white listed and use the port requested by recipient.
# Endpoint-independent (with some limitations.)
# Note: May be incorrectly detected if using TCP.
RESTRICT_PORT_NAT = 5

# Different mapping based on outgoing hosts.
# Even if same source IP and port reused.
# AKA: End-point dependent mapping.
SYMMETRIC_NAT = 6

# No response at all.
BLOCKED_NAT = 7
# ---------------------------------------------------------

# DELTA types: ------------------
# Mappings are easy to reuse and reach.
NA_DELTA = 1 # Not applicable.
EQUAL_DELTA = 2
PRESERV_DELTA = 3 # Or not applicable like in open internet.
INDEPENDENT_DELTA = 4
DEPENDENT_DELTA = 5
RANDOM_DELTA = 6
# -------------------------------

EASY_NATS = [OPEN_INTERNET, FULL_CONE]
DELTA_N = [
    # Remote = Local.
    EQUAL_DELTA,

    # Remote x - y = local x - y
    PRESERV_DELTA,

    # Remote x; y = remote x + delta, local = anything
    INDEPENDENT_DELTA,

    # Remote x; y = remote x + delta only when local x + delta
    DEPENDENT_DELTA,
]

# The NATs here have various properties that allow their
# mappings to be predictable under certain conditions.
PREDICTABLE_NATS = [
    # Once open - anyone can use the mapping.
    FULL_CONE,

    # Same local IP + port = same mapping.
    RESTRICT_NAT,
    
    # Same as above but reply port needs to match original dest.
    RESTRICT_PORT_NAT,

    # Open doesn't really apply so yes.
    OPEN_INTERNET,
]

# NAT types that require specific reply ports.
FUSSY_NATS = [
    RESTRICT_PORT_NAT,
]

# Peer will be unreachable.
BLOCKING_NATS = [
    BLOCKED_NAT
]