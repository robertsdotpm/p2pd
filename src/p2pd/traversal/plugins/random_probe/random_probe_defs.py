"""Constants for the random-probe symmetric NAT traversal plugin."""

# 4-byte magic that prefixes every probe datagram.  Lets the receiver
# distinguish a real probe from internet noise / replays without
# needing per-packet signing.  Picked at random; treat as opaque.
PROBE_MAGIC = b"P2RP"

# Total probe payload length: magic(4) + nonce(16) + role(1) + idx(2)
PROBE_LEN = 4 + 16 + 1 + 2

# Default per-side probe count.  Birthday paradox: both sides draw N
# ports from [PROBE_PORT_LO, PROBE_PORT_HI] = 32768 ports.
# P(at least one match) ~= 1 - exp(-N^2/32768).
# N=256 -> ~86.5% per-direction match (98% bidirectional). The first
# incoming aligned datagram converges the algorithm in milliseconds,
# so per-direction match rate is what actually matters in practice.
#
# DO NOT raise this above 256 without empirical re-testing across the
# matrix. We tried N=512 (anchor sweep, 2026-05-07): random_probe v6
# went 0/2 against the public anchor while udp_punch v6 still passed
# in the same sweep. Dropping back to N=256 restored convergence on
# the first inbound datagram (PASS on srv2022 in 72 s). Suspect cause
# is one of: kernel UDP socket-buffer overrun on the spray burst, NIC
# TX-ring saturation, consumer router stateful v6 flow-table cap, or
# carrier v6 burst rate-limit -- whichever it is, 512 simultaneous v6
# flows from one host trips it and 256 doesn't. udp_punch unaffected
# because it only opens a handful of flows. The math doesn't need 512:
# at N=256 the bidirectional miss rate is already ~2%, so the extra
# flows buy almost nothing in collision probability and cost a real
# regression on v6 paths.
DEFAULT_PROBE_COUNT = 512  # DIAG: temporarily back to 512 for failure-mode confirmation

# Lowest destination port we'll fire at / bind from.  Below 1024 is
# privileged on POSIX and below 32 768 is in many OSes' static-service
# range; sticking to the ephemeral range keeps the random scan
# realistic without the kernel-reserved noise.
PROBE_PORT_LO = 32768
PROBE_PORT_HI = 65535

# How long to keep listening for the first match after firing all
# probes.  Symmetric NATs typically hold UDP mappings for at least
# 30 s; this caps the retry budget without blocking auto_connect
# forever when the algorithm gets unlucky.
PROBE_LISTEN_TIMEOUT = 8

# Roles.  Encoded as a single byte in the probe datagram.
ROLE_CONE = b"\x01"
ROLE_SYM = b"\x02"

# Special probe index used as a "CONFIRM": after the cone receives
# a probe whose source port is in its own destination set (i.e. an
# aligned 4-tuple where the symmetric NAT will route a reply back),
# it sends one final probe with idx=PROBE_IDX_CONFIRM on that
# 4-tuple.  The symmetric side's watcher only locks onto this
# CONFIRM, which is what guarantees both sides agree on the
# winning socket pair without needing to compare extra metadata.
PROBE_IDX_CONFIRM = 0xFFFF
