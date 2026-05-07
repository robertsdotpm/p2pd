"""Sliding-window boundary analysis for port prediction."""
from typing import Tuple
import time
import random

# --- NTP Constants ---
NTP_SERVER = "pool.ntp.org"
NTP_PORT = 123
NTP_DELTA = 2208988800  # 70-year offset between NTP epoch (1900) and Unix epoch (1970)
NTP_PACKET_SIZE = 48
MAX_NTP_RETRIES = 5
NTP_TIMEOUT = 1.0

# --------------------------
# --- Time Rendezvous Constants ---
# WINDOW must be > 2 * MAX_CLOCK_ERROR (2 * 20 = 40) to guarantee both hosts
# select the same time bucket/boundary despite the clock offset.
WINDOW = 42
MAX_CLOCK_ERROR = 20  # The known max clock difference (1-20s)
MIN_RUN_WINDOW = 10  # Minimum time required to run setup before the rendezvous
# NUM_PORTS = TOTAL source-port SYNs each side fires per attempt.
# With the two-bucket overlap port pool (boundary_alloc.py), this is
# split as N//2 per bucket -- so NUM_PORTS=4 yields 2 boundary ports
# from bucket B + 2 from bucket B+1 = 4 deterministic boundary ports
# per fire.  Plus the 2-4 STUN-discovered NAT-predicted ports the
# protocol layer adds, the engine fires 6-8 SYNs concurrently per
# attempt -- comfortably under XP SP2+'s hard 10-concurrent-half-open
# cap (Tcpip Event 4226).
#
# Why so few?
#
# Higher N looks defensive but tripping XP's 10-cap silently queues
# SYNs 11+ past the 5s spray window -- they never go on the wire,
# leaving the matrix dependent on whichever 10 made it.  The 5ms
# spray cadence does NOT keep the half-open count below 10 because
# round-trip time to a public peer (50-100ms) is much longer than
# the per-iteration spray gap, so all N SYNs are simultaneously
# in-flight half-open until SYN-ACK or RST returns.
#
# With deterministic boundary ports + EQUAL_DELTA NAT preservation,
# even ONE matching port per bucket converges if both peers fire at
# the same wall-clock moment.  N=4 boundary gives 2x redundancy per
# bucket against bind collisions, and stays well clear of XP's cap.
NUM_PORTS = 4
BASE_PORT = 2024
# Wider sample space than the original 20000 -- combined with the lower
# BASE_PORT this gives the allocator the full user-port range (~2k-52k),
# which makes collisions across back-to-back runs in the same NTP bucket
# significantly less likely.
PORT_RANGE = 50000
CONNECT_TIMEOUT = 5.0
RETRY_INTERVAL = 0.05
MAX_SLEEP = 10
LARGE_PRIME = 2654435761
# --------------------------

# --------------------------
# --- Punch Parameter Presets ---
#
# DEFAULT_PUNCH_PARAMS: Robust conservative values for CLI / standalone usage.
#   - Large WINDOW (42 s) and MAX_CLOCK_ERROR (20 s) tolerate poor NTP sync.
#   - Rendezvous wait: 10–52 seconds worst-case.
#
# FAST_PUNCH_PARAMS: Tight values for network-protocol usage where punch_time
#   is communicated between peers so both sides use the exact same value.
#   Constraint: window > 2 * max_clock_error  →  6 > 2*2 = 4  ✓
#   - Rendezvous wait: 2–8 seconds.
#   - max_sleep (8 s) is deliberately above the 8 s worst-case remaining wait
#     so sleep_until() does NOT fire early — both sides synchronise exactly.
# --------------------------

DEFAULT_PUNCH_PARAMS = {
    # Time rendezvous
    "window": WINDOW,  # 42 s
    "max_clock_error": MAX_CLOCK_ERROR,  # 20 s
    "min_run_window": MIN_RUN_WINDOW,  # 10 s
    # Engine timing
    "connect_timeout": CONNECT_TIMEOUT,  # 5.0 s spray window
    "monitor_timeout": CONNECT_TIMEOUT,  # 5.0 s monitor window
    "retry_interval": RETRY_INTERVAL,  # 0.05 s selector poll interval
    # PunchClient / plugin timing
    "max_sleep": MAX_SLEEP,  # 10 s cap for sleep_until
    "coordinator_delay": 2.0,  # s delay before spawning punch process
}

FAST_PUNCH_PARAMS = {
    # Time rendezvous — wider window than the original 6 s so cross-host
    # NTP residual drift doesn't push peers into adjacent buckets. The
    # matrix sweep showed XP-after-reboot pairs missing alignment by
    # exactly 1 bucket: NTP-corrected times still drift 4-8 s between
    # XP's slow stack and modern Windows, which is more than the old
    # 2 s max_clock_error tolerance allowed.  Settling on the same
    # values as DEFAULT_PUNCH_PARAMS (40 s of peer-clock tolerance,
    # window > 2 * max_clock_error preserved) accepts a longer
    # rendezvous wait in exchange for far fewer flake failures.
    "window": 42,  # 42 s  (> 2 * 20 s max_clock_error)
    "max_clock_error": 20,  # 20 s  (covers XP NTP residuals + boot drift)
    # min_run_window=10: was 3 to shrink the bucket-fork "skip to next
    # bucket" zone (3/42 = 7% vs 10/42 = 24%).  With the two-bucket
    # overlap port pool + dual-fire rendezvous (boundary_alloc.py +
    # punch_client.run_engine), the bucket-fork zone is no longer a
    # convergence-killer -- both peers always overlap on at least one
    # common (rendezvous_time, port_pool) regardless of which side of
    # the boundary their primary lands.  10 s gives more setup slack
    # per bucket which matters more on slow stacks (XP/Vista) than the
    # smaller fork zone did when there was only a single fire.
    "min_run_window": 10,
    # Engine timing — 5 s gives more SYN-cross opportunities per fire
    # on slow stacks where the kernel's connect() retransmit cadence
    # is slower than typical.  3 s was tight on XP where each spray
    # iteration takes longer due to the older TCP stack; 5 s matches
    # the DEFAULT_PUNCH_PARAMS engine duration and stays well within
    # the dual-fire timeout budget (PLUGIN_CONF=180 s).
    "connect_timeout": 5.0,  # 5.0 s spray window
    "monitor_timeout": 5.0,  # 5.0 s monitor window
    "retry_interval": 0.05,  # 0.05 s selector poll interval (unchanged)
    # PunchClient / plugin timing
    "max_sleep": 65,  # 65 s cap — above worst-case wait of ~62 s
    # (window + max_clock_error) so sleep_until reaches the actual
    # rendezvous time without the cap firing early.
    "coordinator_delay": 0.5,  # 0.5 s — sleep_until handles the actual
    # rendezvous wait; this is just a setup buffer before spawning
    # the punch worker, doesn't need to scale with window.
}


def now_from_network(network_timer: float, network_time: int) -> int:
    """Returns the current Unix timestamp aligned to the NTP reference."""
    elapsed = time.monotonic() - network_timer
    return network_time + int(elapsed)


def quantized_bucket(now: int, window: int = WINDOW, max_error: int = MAX_CLOCK_ERROR) -> int:
    """
    Calculates the time bucket number, robust against clock offsets.
    By subtracting the max error, we shift the timeline so that both hosts,
    regardless of their actual time offset, fall into the same integer bucket.
    """
    return int((now - max_error) // window)


def stable_boundary(bucket: int) -> int:
    """
    Deterministic boundary stable against small clock offsets, used as PRNG seed.
    """
    return (bucket * LARGE_PRIME) % 0xFFFFFFFF


def stable_ports(
boundary: int,
    num_ports: int = NUM_PORTS,
    base_port: int = BASE_PORT,
    port_range: int = PORT_RANGE,
) -> list:
    """
    Deterministic, smooth port selection using PRNG seeded by boundary.
    """
    rng = random.Random(boundary)
    ports = set()
    while len(ports) < num_ports:
        port = base_port + rng.randint(0, port_range - 1)
        ports.add(port)

    return sorted(ports, reverse=True)


# Per-OS port pool for the bucket allocator. The os_token is whatever
# the platform module emitted on the peer (e.g. "Windows-XP",
# "Windows-10", "Linux-5.10.0", "Darwin-22.1.0"). Match by substring so
# we don't have to enumerate every possible release string.
#
# The motivating case is Windows XP. XP's NAT classification is run from
# its normal ephemeral allocator (1025-5000); the FULL_CONE+EQUAL_DELTA
# reading we get back is only valid for sources in that range. The
# default bucket pool (BASE_PORT=2024, PORT_RANGE=50000) picks ports up
# to 52023, well outside XP's classified range -- the router NAT then
# behaves differently than the classifier observed (different mapping
# strategy, sometimes silently rewrites the source port), so the
# external port the peer is told to connect to is wrong and tcp_punch's
# simultaneous-open never converges. Pinning XP's allocator to its
# 1025-5000 pool keeps the bind ports in the range the classifier
# actually validated.
DEFAULT_PORT_POOL = (BASE_PORT, PORT_RANGE)
WINXP_PORT_POOL = (1025, 5000 - 1025 + 1)  # 1025..5000


def port_pool_for_os(os_token):
    """Return (base_port, port_range) for the bucket allocator for os_token.

    os_token is the platform.system()+'-'+platform.release() string the
    peer advertised (or None if the peer didn't ship one). Match by
    substring so unknown future releases of the same OS family route
    to the right pool. Returns DEFAULT_PORT_POOL on unknown OS or None.
    """
    if not os_token:
        return DEFAULT_PORT_POOL
    if "XP" in os_token:
        return WINXP_PORT_POOL
    if "2000" in os_token and "Windows" in os_token:
        return WINXP_PORT_POOL
    return DEFAULT_PORT_POOL


def compute_rendezvous(
now: int,
    window: int = WINDOW,
    min_run_window: int = MIN_RUN_WINDOW,
    max_error: int = MAX_CLOCK_ERROR,
) -> Tuple[int, int]:
    """
    Computes the current time bucket and the rendezvous time (start of the NEXT bucket).
    """
    # 1. Determine the current, shared bucket
    bucket = quantized_bucket(now, window, max_error)

    # 2. Calculate the start of the *next* bucket's valid time window.
    # The rendezvous time is the start of the (bucket + 1) window.
    rendezvous_time = (bucket + 1) * window + max_error

    # 3. Check if there's enough time left for setup. If not, skip to the following bucket.
    if rendezvous_time - now < min_run_window:
        bucket += 1
        rendezvous_time = (bucket + 1) * window + max_error

    return bucket, rendezvous_time
