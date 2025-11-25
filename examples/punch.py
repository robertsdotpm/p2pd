#!/usr/bin/env python3

import sys
import time
import socket
import struct
import selectors
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

def get_ntp_time(server=NTP_SERVER, port=NTP_PORT, retries=MAX_NTP_RETRIES, timeout=NTP_TIMEOUT):
    """
    Fetches the Unix timestamp from an NTP server using UDP sockets, 
    with built-in retry logic for reliability.
    """
    # NTP request message: 48 bytes, setting mode=3 (client), version=4
    # The first byte is 0b00100011 (0x23)
    request_data = b'\x23' + 47 * b'\0' 

    for attempt in range(retries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                # Send the request
                s.sendto(request_data, (server, port))
                # Receive the response
                response_data, _ = s.recvfrom(NTP_PACKET_SIZE)
                
                if len(response_data) < NTP_PACKET_SIZE:
                    raise RuntimeError("NTP response too short")

                # The Transmit Timestamp is the last 8 bytes (offset 40)
                # It is a 64-bit unsigned fixed-point number (seconds + fraction)
                # We unpack the first 4 bytes (seconds part)
                ntp_time_seconds = struct.unpack('!I', response_data[40:44])[0]
                
                # Convert from NTP epoch (1900) to Unix epoch (1970)
                unix_time = ntp_time_seconds - NTP_DELTA
                
                return int(unix_time)

        except socket.timeout:
            print(f"NTP request timed out. Retrying ({attempt + 1}/{retries})...")
            time.sleep(0.1)
        except Exception as e:
            # Handle other socket errors or unpacking issues
            print(f"NTP error on attempt {attempt + 1}: {e}")
            time.sleep(0.1)

    raise RuntimeError(f"Failed to get reliable network time from {server} after {retries} attempts.")


# Network-aligned time reference
try:
    network_time = get_ntp_time()
except RuntimeError as e:
    print(f"CRITICAL ERROR: {e}")
    sys.exit(1)
    
network_timer = time.monotonic()

def now_from_network():
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

def bind_listeners(ports):
    bound = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass # SO_REUSEPORT is not available on all systems
        try:
            s.bind(("0.0.0.0", p))
            s.listen(1)
            bound.append((p, s))
        except OSError as e:
            print(f"Could not bind to port {p}: {e}")
            s.close()
    return bound

def sleep_until(t, max_sleep=MAX_SLEEP):
    now = now_from_network()
    sleep_time = max(0, t - now)
    
    # Cap sleep time to avoid large blocks if the host clock is far behind
    if sleep_time > max_sleep:
        sleep_time = max_sleep
        
    if sleep_time > 0:
        time.sleep(sleep_time)

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

def main():
    if len(sys.argv) != 2:
        print("usage: punch_tcp_networktime.py <dest_host>")
        sys.exit(1)

    dest_host = sys.argv[1]
    try:
        dest_ip = socket.gethostbyname(dest_host)
    except socket.gaierror:
        print(f"Error: Could not resolve host {dest_host}")
        sys.exit(1)

    now = now_from_network()
    bucket, rendezvous_time = compute_rendezvous(now)
    boundary = stable_boundary(bucket)
    ports = stable_ports(boundary)

    print("--- Time Alignment ---")
    print("NTP-aligned current time:", now)
    print(f"Max expected clock error: +/- {MAX_CLOCK_ERROR}s")
    print(f"Time Window Size: {WINDOW}s")
    print("Chosen deterministic bucket:", bucket)
    print("Stable boundary:", boundary)

    print("\n--- Port Selection ---")
    print("Candidate ports:", ports)

    listeners = bind_listeners(ports)
    bound_ports = [p for p, _ in listeners]
    if not bound_ports:
        print("CRITICAL: Failed to bind any ports. Exiting.")
        sys.exit(1)
        
    print("Successfully bound listener ports:", bound_ports)

    print("\n--- Rendezvous ---")
    print("Rendezvous time:", rendezvous_time)
    print("Seconds until punch:", rendezvous_time - now)
    print(f"Sleeping until rendezvous (max {MAX_SLEEP}s)...")
    sleep_until(rendezvous_time)
    print("Starting TCP punch attempt...")

    sel = selectors.DefaultSelector()
    connectors = []

    # Outbound sockets (bind and connect)
    for port in bound_ports: # Only use successfully bound ports
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass

        try:
            # Bind the outbound socket to the same local port as the listener
            s.bind(("0.0.0.0", port))
            # Initiate non-blocking connect (the "punch")
            s.connect_ex((dest_ip, port))
        except OSError as e:
            s.close()
            # print(f"Could not bind/connect outbound on port {port}: {e}")
            continue
            
        connectors.append((port, s))
        sel.register(s, selectors.EVENT_WRITE)

    # Listener sockets
    for port, lsock in listeners:
        sel.register(lsock, selectors.EVENT_READ)

    # Debouncing sets
    completed_outbound = set()
    completed_inbound = set() # This set stores the successful listener sockets

    end = now_from_network() + CONNECT_TIMEOUT
    
    while now_from_network() < end:
        # Check for events on both listeners (read) and connectors (write)
        events = sel.select(timeout=RETRY_INTERVAL)
        
        for key, mask in events:
            sock = key.fileobj
            
            # --- Inbound accept events (Listener Sockets) ---
            if mask & selectors.EVENT_READ:
                # Check if this listener has already accepted a connection
                if sock not in completed_inbound:
                    try:
                        conn, addr = sock.accept()
                        conn.setblocking(False)
                        completed_inbound.add(conn)
                        sel.unregister(sock) # Stop listening on this port

                        # Close listen server sock.
                        sock.close()
                    except Exception:
                        pass # Ignore temporary errors

            # --- Outbound connect events (Connector Sockets) ---
            if mask & selectors.EVENT_WRITE:
                if sock not in completed_outbound:
                    try:
                        err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                        if err == 0:

                            #   2. THE FIX: Verify with getpeername()
                            #    If we aren't truly connected, this throws OSError.
                            sock.getpeername()

                            completed_outbound.add(sock)
                            # Suppress real-time print. Result will be in final summary.
                            
                            sel.unregister(sock) # Stop checking for connection completion
                        else:
                            # Connection failed with error (e.g., ECONNREFUSED)
                            pass
                    except Exception:
                        pass # Ignore exceptions during getsockopt

    # --- FINAL SORTED STATUS DISPLAY ---
    
    print("\n--- Connection Results (Highest Port First) ---")

    # 1. Outbound Connection Successes
    print(f"\nOUTBOUND SUCCESSES ({len(completed_outbound)} total):")
    
    # Sort by local port number (getsockname()[1]) in descending order
    sorted_outbound = sorted(
        completed_outbound, 
        key=lambda s: s.getsockname()[1], 
        reverse=True
    )
    for sock in sorted_outbound:
        local_port = sock.getsockname()[1]
        print(f"<-- Connected to {dest_ip} on port {local_port}")


    # 2. Inbound Connection Successes
    print(f"\nINBOUND SUCCESSES ({len(completed_inbound)} total):")
    
    # completed_inbound holds the listener sockets that accepted a connection.
    # Sort by listener port number (getsockname()[1]) in descending order
    sorted_inbound = sorted(
        completed_inbound, 
        key=lambda s: s.getsockname()[1], 
        reverse=True
    )
    for sock in sorted_inbound:
        listener_port = sock.getsockname()[1]
        # Note: We don't have the client's IP here because we closed 'conn' immediately, 
        # but the connection was successfully established on this port.
        print(f"--> Accepted connection on listener port {listener_port}")

    # Cleanup
    for _, s in connectors:
        if s.fileno() != -1:
            s.close()
    for _, s in listeners:
        if s.fileno() != -1:
            s.close()
    sel.close()

if __name__ == "__main__":
    main()