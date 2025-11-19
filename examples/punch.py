#!/usr/bin/env python3

import sys
import time
import socket
import hashlib
import struct
import selectors
import urllib.request
import json

# --------------------------
WINDOW = 16
MIN_RUN_WINDOW = 10
NUM_PORTS = 16
BASE_PORT = 30000
PORT_RANGE = 20000
CONNECT_TIMEOUT = 5.0
RETRY_INTERVAL = 0.05
FUTURE_OFFSET = 5
MAX_SLEEP = 10
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
        raise RuntimeError(f"Failed to get network time: {e}")

# Fetch network time once and store reference
network_time = get_network_time()
network_timer = time.monotonic()

def now_from_network():
    elapsed = time.monotonic() - network_timer
    return network_time + int(elapsed)

def quantized_bucket(now, window=WINDOW):
    return int((now + FUTURE_OFFSET + window / 2) // window)

def deterministic_boundary(bucket):
    h = hashlib.sha256(str(bucket).encode()).digest()
    return struct.unpack(">I", h[:4])[0]

def deterministic_ports(boundary):
    ports = []
    h = hashlib.sha256(struct.pack(">I", boundary)).digest()
    for i in range(NUM_PORTS):
        start = (i * 2) % (len(h) - 1)
        x = struct.unpack(">H", h[start:start+2])[0]
        port = BASE_PORT + (x % PORT_RANGE)
        ports.append(port)
    return ports

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

def compute_rendezvous(now):
    bucket = quantized_bucket(now, WINDOW)
    rnd = (bucket + 1) * WINDOW
    if rnd - now < MIN_RUN_WINDOW:
        bucket += 1
        rnd = (bucket + 1) * WINDOW
    return bucket, rnd

def main():
    if len(sys.argv) != 2:
        print("usage: punch_tcp_networktime.py <dest_host>")
        sys.exit(1)

    dest_host = sys.argv[1]
    dest_ip = socket.gethostbyname(dest_host)

    now = now_from_network()
    bucket, rendezvous_time = compute_rendezvous(now)
    boundary = deterministic_boundary(bucket)
    ports = deterministic_ports(boundary)

    print("Network-aligned current time:", now)
    print("Chosen bucket:", bucket)
    print("Deterministic boundary:", boundary)
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
                if sock not in completed_inbound:
                    try:
                        conn, addr = sock.accept()
                        conn.setblocking(False)
                        completed_inbound.add((sock, addr))
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
    for sock, addr in sorted(completed_inbound, key=lambda x: x[0].getsockname()[1], reverse=True):
        print("Inbound connection from", addr, "on port", sock.getsockname()[1])

    # Cleanup
    for _, s in connectors:
        s.close()
    for _, s in listeners:
        s.close()

if __name__ == "__main__":
    main()
