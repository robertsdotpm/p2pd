"""
- Closing the STUN socket sends FIN, which can cause some NATs to drop the mapping, so the STUN socket must stay open until punching is finished
- TCP punching requires both peers to send SYN at the same time - sending too early can trigger RST and kill the connection
- Time sync is difficult; NTP can be off by 1-50 ms, which matters
- If timeout is short: in pipe code can tear connections that actually succeeded
- OS scheduling is enough to effect timing
- ProcessPoolExecutor is used so punching happens in child processes, giving more accurate timing and isolating busy connection spam from main app
- Using multiprocessing directly is brittle and works poorly
- Threads do work; but different processes works best
- TCP punching works works badly with blocking sockets and event loops
- The best network code to use is non-blocking polling
- Testing the punchers need different NIC IPs for binding for LAN punch and different WANs for punching over the Internet
- Worst NAT should ideally initiate first so the better NAT can use its received mapping with fewer messages, though this optimization isn't implemented and may not justify added complexity
- Edge case: multiple punches may cause STUN connections from same local endpoint
"""

import selectors
import socket
import os
from .utils import *
from ...utility.punch_utils import *

CONNECT_TIMEOUT = 5.0
RETRY_INTERVAL = 0.05

def setup_engine(af, port_allocs, src_ip, nic_id):
    # The same port is reused for listen() and connect.
    pre_listen_infos = bind_tcp_sockets(af, nic_id, port_allocs, src_ip)
    listen_infos = listen_on_tcp_sockets(pre_listen_infos)
    if not listen_infos:
        raise Exception("Engine failed to listen at all.")

    # Reuse the same listen ports for outbound connects.
    # Hence the cryptic socket options.
    port_allocs = [info[0] for info in listen_infos]
    pre_connect_infos = bind_tcp_sockets(af, nic_id, port_allocs, src_ip)

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

    # When to stop checking for events.
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
                        # Accept a new client socket from the listener.
                        client, addr = sock.accept()
                        client.setblocking(False)

                        # Record the socket.
                        inbound.add(client)

                        # Close the initial server.
                        sock.close()

                        # Don't wait for any more read events.
                        sel.unregister(sock)
                    except Exception:
                        pass # Ignore temporary errors

            # --- Outbound connect events (Connector Sockets) ---
            if mask & selectors.EVENT_WRITE:
                if sock not in outbound:
                    try:
                        err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                        if err == 0:
                            # If we aren't truly connected, this throws OSError.
                            sock.getpeername()

                            # Otherwise safe to record.
                            outbound.add(sock)

                            # Stop checking for connection completion
                            sel.unregister(sock) 
                        else:
                            # Connection failed with error (e.g., ECONNREFUSED)
                            pass
                    except Exception:
                        pass # Ignore exceptions during getsockopt

    return (inbound, outbound,)

def tcp_selector_punch_engine(af, nic_id, port_allocs, src_ip, dest_ip, f_sleep_until, our_ip):
    print("in engine")

    # Create listen sockets, bound con socks, and register for selector events.
    listen_infos, pre_connect_infos, sel = setup_engine(af, port_allocs, src_ip, nic_id)

    # Wait for synchronized punch time frame.
    f_sleep_until()

    # Make outbound connections to the designated ports.
    print("dest ip = ", dest_ip)
    connect_infos = connect_on_tcp_sockets(sel, pre_connect_infos, dest_ip)

    # Return set of successful connections (if any.)
    inbound, outbound = socket_event_monitor(sel)
    if "P2PD_DEBUG" in os.environ:
        for con_set in (inbound, outbound):
            #print(con_set)
            pass

    # chosoe sock(our_wan, sock.getpeer..)
    sock_list = list(inbound) + list(outbound)

    # TODO: Not too sure this code is ideal
    # Might need to just send a header and look for it on the other side.
    sock = choose_winning_tcp_sock(dest_ip, sock_list, our_ip)
    return sock