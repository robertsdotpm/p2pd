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
# --------------------------

def get_network_time(timeout=4.0):
    """
    Get current Unix epoch from a web API.
    Falls back to local time if network fails.
    """
    url = "http://worldtimeapi.org/api/ip"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.load(resp)
            return int(data.get("unixtime", time.time()))
            
    except Exception:
        return int(time.time())

def quantized_bucket(now, window=WINDOW):
    # round to nearest window instead of floor
    return int((now + FUTURE_OFFSET + window/2) // window)

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

def sleep_until(t):
    now = get_network_time()
    if t > now:
        time.sleep(t - now)

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

    now = get_network_time()
    bucket, rendezvous_time = compute_rendezvous(now)
    boundary = deterministic_boundary(bucket)
    ports = deterministic_ports(boundary)

    print("Network-based current time:", now)
    print("Chosen bucket:", bucket)
    print("Deterministic boundary:", boundary)
    print("Candidate ports:", ports)

    listeners = bind_listeners(ports)
    bound_ports = [p for p, _ in listeners]
    print("Successfully bound listener ports:", bound_ports)

    print("Rendezvous time:", rendezvous_time)
    print("Seconds until rendezvous:", rendezvous_time - now)
    print("Sleeping until rendezvous...")
    sleep_until(rendezvous_time)
    print("Punching at rendezvous time")

    sel = selectors.DefaultSelector()
    connectors = []

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

    for port, lsock in listeners:
        sel.register(lsock, selectors.EVENT_READ)

    end = get_network_time() + CONNECT_TIMEOUT
    while get_network_time() < end:
        events = sel.select(timeout=RETRY_INTERVAL)
        for key, mask in events:
            sock = key.fileobj
            if mask & selectors.EVENT_READ:
                try:
                    conn, addr = sock.accept()
                    conn.setblocking(False)
                    print("Inbound connection from", addr, "on port", sock.getsockname()[1])
                    conn.close()
                except Exception:
                    pass
            if mask & selectors.EVENT_WRITE:
                try:
                    err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if err == 0:
                        print("Outbound connect success on port", sock.getsockname()[1])
                    else:
                        try:
                            sock.connect_ex((dest_ip, sock.getsockname()[1]))
                        except Exception:
                            pass
                except Exception:
                    pass

    for _, s in connectors:
        s.close()
    for _, s in listeners:
        s.close()

if __name__ == "__main__":
    main()
