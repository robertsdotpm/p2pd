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
NUM_PORTS = 16
BASE_PORT = 30000
PORT_RANGE = 20000
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
    # Time rendezvous — much tighter window for protocol-coordinated punching.
    # punch_time is communicated via PunchMsg so independent NTP alignment is
    # not required; we just need window > 2 * max_clock_error for bucket safety.
    "window": 6,  # 6 s  (> 2 * 2 s max_clock_error)
    "max_clock_error": 2,  # 2 s  (NTP is typically < 0.5 s; 2 s is conservative)
    "min_run_window": 2,  # 2 s  (enough for protocol exchange + process startup)
    # Engine timing — bumped from 2.0 to 3.0 each after the matrix sweep
    # showed udp_punch flaking on busy hosts. With 18 sockets each spraying
    # at 50 Hz the connector saw only 1/18 of expected PROBEs back -- the
    # asyncio executor thread couldn't keep up with the 2 s window under
    # MQTT broker churn + plugin coordination chatter. 3 s gives ~50%
    # headroom on both directions, still well below DEFAULT_PUNCH_PARAMS's
    # 5.0 s and well within plugin's 30/40 s timeout.
    "connect_timeout": 5.0,  # 5.0 s spray window (total ~10s with monitor)
    "monitor_timeout": 5.0,  # 5.0 s monitor window
    "retry_interval": 0.05,  # 0.05 s selector poll interval (unchanged)
    # PunchClient / plugin timing
    "max_sleep": 8,  # 8 s cap — above worst-case (window + min_run_window)
    # so sleep_until reaches the actual rendezvous time.
    "coordinator_delay": 0.5,  # 0.5 s delay (reduced from 2 s)
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
