import time
import random

# --- NTP Constants ---
NTP_SERVER = "pool.ntp.org"
NTP_PORT = 123
NTP_DELTA = 2208988800 # 70-year offset between NTP epoch (1900) and Unix epoch (1970)
NTP_PACKET_SIZE = 48
MAX_NTP_RETRIES = 5
NTP_TIMEOUT = 1.0

# --------------------------
# --- Time Rendezvous Constants ---
# WINDOW must be > 2 * MAX_CLOCK_ERROR (2 * 20 = 40) to guarantee both hosts 
# select the same time bucket/boundary despite the clock offset.
WINDOW = 42
MAX_CLOCK_ERROR = 20 # The known max clock difference (1-20s)
MIN_RUN_WINDOW = 10  # Minimum time required to run setup before the rendezvous
NUM_PORTS = 16
BASE_PORT = 30000
PORT_RANGE = 20000
CONNECT_TIMEOUT = 5.0
RETRY_INTERVAL = 0.05
MAX_SLEEP = 10
LARGE_PRIME = 2654435761
# --------------------------

def now_from_network(network_timer, network_time):
    """Returns the current Unix timestamp aligned to the NTP reference."""
    elapsed = time.monotonic() - network_timer
    return network_time + int(elapsed)

def quantized_bucket(now, window=WINDOW, max_error=MAX_CLOCK_ERROR):
    """
    Calculates the time bucket number, robust against clock offsets.
    By subtracting the max error, we shift the timeline so that both hosts, 
    regardless of their actual time offset, fall into the same integer bucket.
    """
    return int((now - max_error) // window)

def stable_boundary(bucket):
    """
    Deterministic boundary stable against small clock offsets, used as PRNG seed.
    """
    return (bucket * LARGE_PRIME) % 0xFFFFFFFF

def stable_ports(boundary, num_ports=NUM_PORTS, base_port=BASE_PORT, port_range=PORT_RANGE):
    """
    Deterministic, smooth port selection using PRNG seeded by boundary.
    """
    rng = random.Random(boundary)
    ports = set()
    while len(ports) < num_ports:
        port = base_port + rng.randint(0, port_range - 1)
        ports.add(port)
        
    return sorted(ports, reverse=True)

def compute_rendezvous(now, window=WINDOW, min_run_window=MIN_RUN_WINDOW, max_error=MAX_CLOCK_ERROR):
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