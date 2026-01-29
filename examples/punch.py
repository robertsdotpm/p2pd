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
    request_data = b'\x23' + 47 * b'\0'

    for attempt in range(retries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(request_data, (server, port))
                response_data, _ = s.recvfrom(NTP_PACKET_SIZE)

                if len(response_data) < NTP_PACKET_SIZE:
                    raise RuntimeError("NTP response too short")

                ntp_time_seconds = struct.unpack('!I', response_data[40:44])[0]
                unix_time = ntp_time_seconds - NTP_DELTA
                return int(unix_time)

        except Exception:
            time.sleep(0.1)

    raise RuntimeError(f"Failed to get reliable network time from {server}.")


# Network-aligned time reference
network_time = get_ntp_time()
network_timer = time.monotonic()

def now_from_network():
    """Returns the current Unix timestamp aligned to the NTP reference."""
    return network_time + int(time.monotonic() - network_timer)


def quantized_bucket(now, window=WINDOW, max_error=MAX_CLOCK_ERROR):
    """
    Calculates the time bucket number, robust against clock offsets.
    """
    return int((now - max_error) // window)


def stable_boundary(bucket):
    """Deterministic boundary stable against small clock offsets."""
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


def bind_active_sockets(ports):
    """
    TCP hole punching uses ONE socket per port.
    No listen sockets. Each socket performs active open only.
    """
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
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_SYNCNT, 2)
        except Exception:
            pass

        try:
            s.bind(("0.0.0.0", p))
            bound.append((p, s))
        except OSError as e:
            print(f"Could not bind to port {p}: {e}")
            s.close()

    return bound


def sleep_until(t, max_sleep=MAX_SLEEP):
    now = now_from_network()
    sleep_time = max(0, t - now)
    if sleep_time > max_sleep:
        sleep_time = max_sleep
    if sleep_time > 0:
        time.sleep(sleep_time)


def compute_rendezvous(now):
    """
    Computes the current time bucket and the rendezvous time (start of the NEXT bucket).
    """
    bucket = quantized_bucket(now)
    rendezvous_time = (bucket + 1) * WINDOW + MAX_CLOCK_ERROR
    if rendezvous_time - now < MIN_RUN_WINDOW:
        bucket += 1
        rendezvous_time = (bucket + 1) * WINDOW + MAX_CLOCK_ERROR
    return bucket, rendezvous_time


def main():
    if len(sys.argv) != 2:
        print("usage: punch_tcp_networktime.py <dest_host>")
        sys.exit(1)

    dest_ip = socket.gethostbyname(sys.argv[1])

    now = now_from_network()
    bucket, rendezvous_time = compute_rendezvous(now)
    boundary = stable_boundary(bucket)
    ports = stable_ports(boundary)

    print("Candidate ports:", ports)

    sockets = bind_active_sockets(ports)
    if not sockets:
        print("CRITICAL: Failed to bind any ports. Exiting.")
        sys.exit(1)

    print("Bound active punch ports:", [p for p, _ in sockets])

    print("Sleeping until rendezvous...")
    sleep_until(rendezvous_time)

    sel = selectors.DefaultSelector()
    for _, s in sockets:
        sel.register(s, selectors.EVENT_WRITE | selectors.EVENT_READ)

    end = now_from_network() + CONNECT_TIMEOUT
    successful = set()

    while now_from_network() < end:

        # SYN spray loop — repeated connect_ex drives TCP state machine
        for p, s in sockets:
            try:
                s.connect_ex((dest_ip, p))
            except Exception:
                pass

        events = sel.select(timeout=RETRY_INTERVAL)

        for key, mask in events:
            sock = key.fileobj

            # WRITE = connect completion path
            if mask & selectors.EVENT_WRITE:
                try:
                    if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                        sock.getpeername()
                        successful.add(sock)
                except Exception:
                    pass

            # READ = simultaneous-open completion or live traffic
            if mask & selectors.EVENT_READ:
                try:
                    sock.recv(1, socket.MSG_PEEK)
                    successful.add(sock)
                except BlockingIOError:
                    successful.add(sock)
                except Exception:
                    pass

    print("\n--- SUCCESSFUL TCP PUNCH SOCKETS ---")
    for s in sorted(successful, key=lambda x: x.getsockname()[1], reverse=True):
        print(f"Connected on local port {s.getsockname()[1]}")

    for _, s in sockets:
        s.close()
    sel.close()


if __name__ == "__main__":
    main()
