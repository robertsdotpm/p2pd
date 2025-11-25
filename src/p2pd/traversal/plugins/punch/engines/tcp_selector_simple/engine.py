"""
FIN and RST on close:

Something important to note about TCP hole punching: suppose your NAT type is one that reuses mappings under certain conditions. You go ahead and use STUN to setup the mapping and then retrieve what it is. At this point if you were to go ahead and close() the socket used for the STUN transactions it would send out a 'FIN' packet. 

Now, if the router saw that FIN it may decide to close the port mapping. We would hope that multiple outbound connections with the same local tuple to different destinations would mean that a single FIN wouldn't cause the NAT to disregard other packets. But in any case the STUN connection ought to stay open at least until the TCP punching has been completed.

Synchronicity:

TCP hole punching between two peers heavily depends on synchronized actions.
If a peer sends a SYN too early then they risk having the other side's NAT
send back an RST which will cause the connection to be closed even if the
connection later 'succeeds.' Therefore, writing one of the peers to
'start sooner' than an agreed upon time simply makes their connection unstable.
The correct way to do TCP hole punching is to start at the same time but
synchronicity between networked devices is a notoriously hard problem to solve.

Using the NTP protocol it can be off by between 1 - 50 ms which is significant
enough to matter. The algorithm tries to compensate by sampling and using
statistical methods to remove outliers. The original approach for this was
taken from the Gnuttella code (written in C) and ported to Python.

Wait times:

The protocol is meant to take up to N seconds to complete. Where N is enough
time to receive initial mappings and / or updated mappings + a buffer for
synchronized startup. There is also a limit on the whole process imposed
by the 'pipe waiter' code that waits for a pipe to be returned. If the
limit is too short then you may see connections succeed in the punching
code but then be tore down from the timeout cleanup code. I wanted to
make a note of this here. I am trying to minimize how much time is spent
sleeping so that the process is faster but I am still tweaking this.

Sharing sockets between processes:

The TCP punch module uses Python's ProcessPoolExecutor to spawn child processes
that do the punching operations. Using this design has several benefits. It
means that the timing between peers is slightly more accurate as the main process
is not interrupting the connection code. In reality though: the operating system
still controls scheduling of processes (without using special code to pin the
processes to certain cores.)

Another benefit is that parts of the code which are very 'busy' such as the local
punching algorithm (which essentially just spams connections as much as it can)
will not impact the performance of the main application. There is a consequence
to this design though. If a process exits then presumably the socket descriptors
opened from the process will become unusable. Fortunately, Python's process pool
spins up a list of processes (by default set to the core number) and reuses them.
That means that the sockets should remain valid through the software's lifetime.

Event loops:

On Linux, Mac OS X, BSD... The default event loop is the selector event loop.
On Windows the default event loop is the proactor event loop. When it comes
to running commands and making 'pipes' to processes you need to use the
proactor event loop on Windows. But for TCP hole punching to work the
selector event loop is the only one that seems to make the code work.

When running async code for the first time in an 'executor' / new process
it will need to create a new event loop. Normally this would have quite
a delay. In order to make async code run fast I pre-initialize all executors
with a call to create an event loop. So when async code is run in them
there is no startup penalty. This is important for timing-based code.

Testing:

When it comes to testing punching on the same machine it is 
sometimes necessary to run the punching code in separate processes (with their
own event loops.) Otherwise, they will interfere with each other and the
syns won't cross in time. Ideally each process should be running on its
own core with a high priority. But this is hard to guarantee in practice.

Edge-case: making another connection to the same STUN server, from the same local endpoint due to another TCP punch occurring.

Notes:

- It makes sense for the combination of the worst NAT + delta type
to go first since it means the better NAT is put in the position
of assuming receipt of their initial mappings which it can then
try to use for its own external mappings without the need to
successfully return back updated mappings. Making only one initial
message necessary to do the punching. But for now -- this is not
done. If some kind of reverse start logic is needed then it
would itself require another message. So maybe not worth the cost.
"""

import selectors
import socket
import os
from .utils import *
from ...utility.punch_utils import *

CONNECT_TIMEOUT = 5.0
RETRY_INTERVAL = 0.05

def setup_engine(af, port_allocs, src_ip):
    # The same port is reused for listen() and connect.
    pre_listen_infos = bind_tcp_sockets(af, port_allocs, src_ip)
    listen_infos = listen_on_tcp_sockets(pre_listen_infos)
    if not listen_infos:
        raise Exception("Engine failed to listen at all.")

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

def tcp_selector_punch_engine(af, port_allocs, src_ip, dest_ip, f_sleep_until, our_ip):
    # Create listen sockets, bound con socks, and register for selector events.
    listen_infos, pre_connect_infos, sel = setup_engine(af, port_allocs, src_ip)

    # Wait for synchronized punch time frame.
    f_sleep_until()

    # Make outbound connections to the designated ports.
    connect_infos = connect_on_tcp_sockets(sel, pre_connect_infos, dest_ip)

    # Return set of successful connections (if any.)
    inbound, outbound = socket_event_monitor(sel)

    # chosoe sock(our_wan, sock.getpeer..)
    sock_list = list(inbound) + list(outbound)
    sock = choose_winning_tcp_sock(dest_ip, sock_list, our_ip)

    # TODO: choose winning socks
    if "P2PD_DEBUG" in os.environ:
        for con_set in (inbound, outbound):
            print(con_set)

    return sock