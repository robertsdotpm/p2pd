import selectors
import socket
import sys
from .utils import *

CONNECT_TIMEOUT = 5.0
RETRY_INTERVAL = 0.05

def setup_engine(af, port_allocs, src_ip):
    # The same port is reused for listen() and connect.
    pre_listen_infos = bind_tcp_sockets(af, port_allocs, src_ip)
    listen_infos = listen_on_tcp_sockets(pre_listen_infos)
    if not listen_infos:
        print("CRITICAL: Failed to bind any ports. Exiting.")
        sys.exit(1)

    # Reuse the same listen ports for outbound connects.
    # Hence the cryptic socket options.
    port_allocs = [info[0] for info in listen_infos]
    pre_connect_infos = bind_tcp_sockets(af, port_allocs, src_ip)

    # Register listening sockets for events.
    sel = selectors.DefaultSelector()
    for listen_info in listen_infos:
        _, s = listen_info
        sel.register(s, selectors.EVENT_READ)

    return (listen_infos, pre_connect_infos, sel)

def socket_event_monitor(sel):
    # Debouncing sets
    outbound = set()

    # This set stores the successful listener sockets
    inbound = set() 

    start_time = time.monotonic()
    end = start_time + CONNECT_TIMEOUT
    while time.monotonic() < end:
        # Check for events on both listeners (read) and connectors (write)
        events = sel.select(timeout=RETRY_INTERVAL)
        for key, mask in events:
            sock = key.fileobj
            
            # --- Inbound accept events (Listener Sockets) ---
            if mask & selectors.EVENT_READ:
                # Check if this listener has already accepted a connection
                if sock not in inbound:
                    try:
                        conn, addr = sock.accept()
                        conn.setblocking(False)
                        inbound.add(sock)
                        # Suppress real-time print. Result will be in final summary.
                        conn.close()
                        sel.unregister(sock) # Stop listening on this port
                    except Exception:
                        pass # Ignore temporary errors

            # --- Outbound connect events (Connector Sockets) ---
            if mask & selectors.EVENT_WRITE:
                if sock not in outbound:
                    try:
                        err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                        if err == 0:
                            outbound.add(sock)

                            # Suppress real-time print. Result will be in final summary.
                            sel.unregister(sock) # Stop checking for connection completion
                        else:
                            # Connection failed with error (e.g., ECONNREFUSED)
                            pass
                    except Exception:
                        pass # Ignore exceptions during getsockopt

    return (inbound, outbound,)

def tcp_selector_punch_engine(af, port_allocs, src_ip, dest_ip, f_sleep_until):
    # Create listen sockets, bound con socks, and register for selector events.
    listen_infos, pre_connect_infos, sel = setup_engine(af, port_allocs, src_ip)

    # Wait for synchronized punch time frame.
    print("Waiting until punch time.")
    f_sleep_until()

    # Make outbound connections to the designated ports.
    connect_infos = connect_on_tcp_sockets(pre_connect_infos, dest_ip)

    # Register connect sockets for writes.
    for con_info in pre_connect_infos:
        _, s = con_info
        sel.register(s, selectors.EVENT_WRITE)

    # Return set of successful connections (if any.)
    inbound, outbound = socket_event_monitor(sel)

    for con_set in (inbound, outbound):
        print(con_set)
