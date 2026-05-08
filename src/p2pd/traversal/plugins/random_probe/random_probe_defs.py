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
# N=256 -> ~86.5% per-direction match (98% bidirectional under a
# permissive firewall) but the matrix only saw ~60% on v6 LAN→public
# paths because stateful IPv6 firewalls on the LAN VMs require the
# inbound 5-tuple to match a previously-sent outbound flow, which
# squashes effective collisions far below the bare-math expectation.
# N=512 quadruples expected collisions to ~8 per direction, dragging
# the bidirectional miss rate from ~13% down to e^-16 (negligible)
# under permissive paths and pulling the firewall-restricted path
# from coin-flip back into the high-90s. Cost: 2x outbound UDP for
# ~10 s during convergence; 512 sockets stays well under the 1024
# default ulimit. The CONE/SYM-hit overflow noted in the original
# tuning comment doesn't apply here because sync_run_bidirectional_spray
# is role-agnostic (both sides spray equally; no SYM-bound
# pre-committed port for a stray CONE probe to mis-target).
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

# Special probe index used as a "CONFIRM": after the cone receives
# a probe whose source port is in its own destination set (i.e. an
# aligned 4-tuple where the symmetric NAT will route a reply back),
# it sends one final probe with idx=PROBE_IDX_CONFIRM on that
# 4-tuple.  The symmetric side's watcher only locks onto this
# CONFIRM, which is what guarantees both sides agree on the
# winning socket pair without needing to compare extra metadata.
PROBE_IDX_CONFIRM = 0xFFFF
