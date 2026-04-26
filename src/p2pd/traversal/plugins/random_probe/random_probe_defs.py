"""Constants for the random-probe symmetric NAT traversal plugin."""

# 4-byte magic that prefixes every probe datagram.  Lets the receiver
# distinguish a real probe from internet noise / replays without
# needing per-packet signing.  Picked at random; treat as opaque.
PROBE_MAGIC = b"P2RP"

# Total probe payload length: magic(4) + nonce(16) + role(1) + idx(2)
PROBE_LEN = 4 + 16 + 1 + 2

# Default per-side probe count.  Birthday paradox: with N=256 probes
# each, P(collision somewhere in 65 535 ports) ~= 1 - exp(-N^2/65535)
# ~= 0.63.  N=350 gets you ~0.85.  Tailscale uses 256 in their blog
# write-up and that's what we default to.
DEFAULT_PROBE_COUNT = 256

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
