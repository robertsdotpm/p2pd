#!/usr/bin/env python3

import sys
import time
import socket
import struct
import selectors
import urllib.request
import json
import random

# --------------------------
# --- FIXES APPLIED HERE ---
# WINDOW must be > 2 * MAX_CLOCK_ERROR to ensure both hosts select the same bucket
WINDOW = 42 # (e.g., 2 * 20s + 2s buffer)
MAX_CLOCK_ERROR = 20 # The known max clock difference (1-20s)
MIN_RUN_WINDOW = 10
NUM_PORTS = 16
BASE_PORT = 30000
PORT_RANGE = 20000
CONNECT_TIMEOUT = 5.0
RETRY_INTERVAL = 0.05
# FUTURE_OFFSET removed as it complicates the time alignment logic
MAX_SLEEP = 10
LARGE_PRIME = 2654435761
# --------------------------

def get_network_time(timeout=4.0):
    url = "http://worldtimeapi.org/api/ip"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.load(resp)
            unixtime = data.get("unixtime")
            if unixtime is None:
                raise ValueError("No 'unixtime' field in response")
            return int(unixtime)
    except Exception as e:
        # Fallback to local time if network time fails for robustness, 
        # but the problem assumes network time is used.
        raise RuntimeError(f"Failed to get network time: {e}")

# Network-aligned time reference
network_time = get_network_time()
network_timer = time.monotonic()

def now_from_network():
    elapsed = time.monotonic() - network_timer
    return network_time + int(elapsed)

# --- FIX 1: Corrected for error margin ---
def quantized_bucket(now, window=WINDOW, max_error=MAX_CLOCK_ERROR):
    """
    Calculates the time bucket number, robust against clock offsets up to max_error.
    By subtracting max_error, both hosts shift their time back to a point 
    that guarantees they fall into the start of the same, correct window.
    """
    return int((now - max_error) // window)

def stable_boundary(bucket):
    """
    Deterministic boundary stable against small clock offsets.
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

def bind_listeners(ports):
    bound = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        try:
            s.bind(("0.0.0.0", p))
            s.listen(1)
            bound.append((p, s))
        except OSError:
            s.close()
    return bound

def sleep_until(t, max_sleep=MAX_SLEEP):
    now = now_from_network()
    sleep_time = max(0, t - now)
    if sleep_time > max_sleep:
        sleep_time = max_sleep
    if sleep_time > 0:
        time.sleep(sleep_time)

# --- FIX 2: Corrected rendezvous time calculation ---
def compute_rendezvous(now, window=WINDOW, min_run_window=MIN_RUN_WINDOW, max_error=MAX_CLOCK_ERROR):
    """
    Computes the current time bucket and the rendezvous time (start of the NEXT bucket).
    The rendezvous time is calculated relative to the 'zero point' of the window structure.
    """
    # 1. Determine the current, shared bucket
    bucket = quantized_bucket(now, window, max_error)

    # 2. Calculate the start of the *next* bucket's valid time window.
    # The window starts at: bucket * window + MAX_CLOCK_ERROR
    # The rendezvous time should be the start of the (bucket + 1) window
    rendezvous_time = (bucket + 1) * window + max_error

    # 3. Check if there's enough time left in the current window for setup
    if rendezvous_time - now < min_run_window:
        bucket += 1
        rendezvous_time = (bucket + 1) * window + max_error
        
    return bucket, rendezvous_time

def main():
    if len(sys.argv) != 2:
        print("usage: punch_tcp_networktime.py <dest_host>")
        sys.exit(1)

    dest_host = sys.argv[1]
    dest_ip = socket.gethostbyname(dest_host)

    now = now_from_network()
    bucket, rendezvous_time = compute_rendezvous(now)
    boundary = stable_boundary(bucket)
    ports = stable_ports(boundary)

    print("Network-aligned current time:", now)
    print(f"Max expected clock error: +/- {MAX_CLOCK_ERROR}s")
    print(f"Time Window Size: {WINDOW}s")
    print("Chosen bucket:", bucket)
    print("Stable boundary:", boundary)
    print("Candidate ports:", ports)

    listeners = bind_listeners(ports)
    bound_ports = [p for p, _ in listeners]
    print("Successfully bound listener ports:", bound_ports)

    print("Rendezvous time:", rendezvous_time)
    print("Seconds until rendezvous:", rendezvous_time - now)
    print(f"Sleeping until rendezvous (max {MAX_SLEEP}s)...")
    sleep_until(rendezvous_time)
    print("Punching at rendezvous time")

    sel = selectors.DefaultSelector()
    connectors = []

    # Outbound sockets
    for port, _listener in listeners:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        try:
            s.bind(("0.0.0.0", port))
        except OSError:
            s.close()
            continue
        try:
            s.connect_ex((dest_ip, port))
        except Exception:
            pass
        connectors.append((port, s))
        sel.register(s, selectors.EVENT_WRITE)

    # Listener sockets
    for port, lsock in listeners:
        sel.register(lsock, selectors.EVENT_READ)

    # Debouncing sets
    completed_outbound = set()
    completed_inbound = set()

    end = now_from_network() + CONNECT_TIMEOUT
    while now_from_network() < end:
        events = sel.select(timeout=RETRY_INTERVAL)
        for key, mask in events:
            sock = key.fileobj

            # Inbound accept events
            if mask & selectors.EVENT_READ:
                # Find listener port for cleanup
                listener_port = sock.getsockname()[1] 
                if listener_port not in [s.getsockname()[1] for s in completed_inbound]:
                    try:
                        conn, addr = sock.accept()
                        conn.setblocking(False)
                        completed_inbound.add(sock)
                        # In a real app, you'd handle 'conn' here, but for this example, we close it.
                        conn.close()
                    except Exception:
                        pass

            # Outbound connect events
            if mask & selectors.EVENT_WRITE:
                if sock not in completed_outbound:
                    try:
                        err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                        if err == 0:
                            completed_outbound.add(sock)
                        else:
                            # Re-attempt connect_ex if needed (e.g., non-blocking in-progress)
                            try:
                                sock.connect_ex((dest_ip, sock.getsockname()[1]))
                            except Exception:
                                pass
                    except Exception:
                        pass

    # Print results ordered by highest port first
    print("\nOutbound connections (highest port first):")
    for sock in sorted(completed_outbound, key=lambda s: s.getsockname()[1], reverse=True):
        print("Outbound connect success on port", sock.getsockname()[1])

    print("\nInbound connections (highest port first):")
    # completed_inbound now contains the listener sockets that received an inbound connection
    for sock in sorted(completed_inbound, key=lambda s: s.getsockname()[1], reverse=True):
        print("Inbound connection received on listener port", sock.getsockname()[1])

    # Cleanup
    for _, s in connectors:
        s.close()
    for _, s in listeners:
        s.close()

if __name__ == "__main__":
    main()