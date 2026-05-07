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
# NUM_PORTS = number of source-port SYNs each side fires at the peer's
# single predicted dest port. Higher N = more chances to converge when
# port prediction has any error (e.g. XP's non-monotonic ephemeral
# allocator producing wider mapping spread). Cap is set by the
# tightest concurrent-half-open limit in the matrix: Windows XP SP2+
# defaults to 10 (Tcpip Event 4226). 8 leaves headroom under that cap
# while giving 4x more pairs to converge on than the previous 2.
# When db0c676 dropped this from 16->2 (intent: fit XP's 10-cap with
# margin), it meanwhile relied on punch_client's hard-coded n=16
# default to keep the actual punch using 16. That hardcode was later
# removed in 2a36880, exposing NUM_PORTS=2 for the first time and
# silently breaking XP tcp_punch convergence -- 2 chances per punch
# is too few when prediction is even slightly off.
NUM_PORTS = 8
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
    # min_run_window=10 was inherited from DEFAULT_PUNCH_PARAMS, which
    # sized it for *manual CLI* usage where a human types ssh commands
    # on two machines and needs ~10s of slack to start both sides.
    # Network-protocol invocation completes setup in <1s after PunchMsg
    # arrives -- 10s is wildly conservative and was the actual cause of
    # the bucket-fork failures we saw (~5% sweep flake): two peers with
    # NTP-correct clocks 0.79s apart straddled the 10s "skip to next
    # bucket" threshold, one bumped, the other didn't, and they ended
    # up firing 42s apart on different ports.  Dropping to 3 s shrinks
    # the fork window from 10/42=24% of every bucket transition to
    # 3/42=7%; together with the small absolute setup cost (~100 ms
    # for socket binds) this is comfortably enough headroom.
    # Reverted to 10 (XP-test): the 3 s value made XP tcp_punch (both v4
    # and v6) stop emitting log output between PunchMsg-receive and the
    # actual fire, suggesting the bucket-bump path or the rendezvous
    # wait was getting starved on XP's slow process / clock setup. Keep
    # 10 until we have a deterministic repro for the bucket-fork issue
    # on faster hosts; the XP regression is more important.
    "min_run_window": 10,
    # Engine timing — bumped from 2.0 to 3.0 each after the matrix sweep
    # showed udp_punch flaking on busy hosts. With 18 sockets each spraying
    # at 50 Hz the connector saw only 1/18 of expected PROBEs back -- the
    # asyncio executor thread couldn't keep up with the 2 s window under
    # MQTT broker churn + plugin coordination chatter. 3 s gives ~50%
    # headroom on both directions, still well below DEFAULT_PUNCH_PARAMS's
    # 5.0 s and well within plugin's 30/40 s timeout.
    "connect_timeout": 3.0,  # 3.0 s spray window (5.0 caused regression)
    "monitor_timeout": 3.0,  # 3.0 s monitor window
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
