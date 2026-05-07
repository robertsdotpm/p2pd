"""
Tricks to pass FDs around processes work well with threading.
But the approach is --not-- reliable for every OS. The best design
so far is just having a reverse connecting back to a listen server
in the main process (like so):

            punch proc             |      main proc
---------------------------------------------------------
remote client <---- punched sock   |  reverse server accept():
                    reverse sock ---->  punch proc connection
                                   |
        sock forwarding agent      |
    --------------------------     |
punched sock <---> reverse sock    |
                                   |
punched sock <---> reverse sock <-----> punch proc connection


Why the loopback bridge (listener on 0.0.0.0, worker connects 127.0.0.1)
=======================================================================

The "punch proc" runs in a ThreadPoolExecutor worker thread (see
docstring on punching_process below for why we left the
ProcessPoolExecutor model). Threading does mean the parent and
worker share an address space, so in principle the worker could
hand the punched socket directly to the main asyncio loop -- no
serialisation, no Reduction trick.

In practice we don't, for two reasons:

  1. The asyncio selector is bound to the main thread's event loop.
     Sockets created or connected on the worker thread can't be
     registered with the main loop's selector cleanly: cross-thread
     fd registration races the selector's poll cycle and silently
     drops events on some platforms (Windows ProactorEventLoop is
     particularly hostile, but even our SelectorEventLoop has
     ordering issues when add_reader fires from a non-loop thread).
     Routing the punched socket through a fresh connect from worker
     -> listener-in-main-loop sidesteps the whole class of problem:
     the kernel hands the main loop a freshly-accepted socket that
     it owns from the start.

  2. We need a one-shot rendezvous between worker and main process
     anyway, because the worker is firing the simultaneous-open
     spray on the BLOCKING side (5s in tcp_punch_utils.py:255). The
     main loop has to keep handling MQTT signaling, plugin lifecycle
     timeouts, and other plugin attempts during that 5s. A
     listen-server in the main loop is already the simplest way to
     synchronise "worker is done, here is the result" without
     polling shared state.

The listener is bound to 0.0.0.0 / :: (any address) rather than
the NIC IP, and the worker connects back to 127.0.0.1 / ::1, for
two more reasons:

  - The bridge is ALWAYS same-host (worker thread to main loop).
    There's no reason to traverse the NIC. Loopback shaves out one
    layer of routing and any NIC-driver / firewall interaction.

  - On Windows XP, a TCP connect FROM the NIC IP back to the SAME
    NIC IP can hit the strong host model and get refused with
    WinError 10061 ("connection refused"). Vista+ silently routes
    same-NIC-to-same-NIC through loopback so the bug never showed
    on later OSes -- but it bit us on XP. Routing the worker's
    reverse-connect through 127.0.0.1 removes the class of host-
    model and NIC-routing risk regardless of OS version.
"""

from typing import Any, Optional
import asyncio
import signal
import socket
from aionetiface import Pipe, TCP, log, log_exception, async_wrap_errors
from .tcp_punch_engine import tcp_selector_punch_engine
from aionetiface.net.selector_proxy import selector_proxy


def punching_process(puncher: Any, reverse_server_dest: Any, stop_reader: Any) -> None:
    """Run the blocking punch engine and proxy the result back through a reverse connection.

    Despite the name, this currently runs in a ThreadPoolExecutor
    worker thread (the previous ProcessPoolExecutor was unstable on
    Windows Python 3.8 -- see node_utils.get_pp_executors). Catch
    ValueError too because signal.signal() raises that when called
    outside the main thread, and the SIGINT handler is pointless
    in a worker thread anyway (signals route to the main thread).
    """
    print("[PUNCH-WORKER] enter af={0} src_ip={1} dest_ip={2} "
          "port_allocs={3} reverse_dest={4}".format(
              getattr(puncher, "af", None),
              getattr(puncher, "src_ip", None),
              getattr(puncher, "dest_ip", None),
              len(getattr(puncher, "port_allocs", []) or []),
              reverse_server_dest,
          ), flush=True)
    log("[PUNCH-WORKER] enter af={0} src_ip={1} dest_ip={2} "
        "port_allocs={3} reverse_dest={4}".format(
            getattr(puncher, "af", None),
            getattr(puncher, "src_ip", None),
            getattr(puncher, "dest_ip", None),
            len(getattr(puncher, "port_allocs", []) or []),
            reverse_server_dest,
        ))
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (OSError, AttributeError, ValueError):
        pass
    try:
        # New punched TCP sock to destination.
        print("[PUNCH-WORKER] calling run_engine", flush=True)
        log("[PUNCH-WORKER] calling run_engine")
        punched_sock = puncher.run_engine(tcp_selector_punch_engine)
        if not punched_sock:
            print("[PUNCH-WORKER] run_engine returned no socket -- punch failed", flush=True)
            log("[PUNCH-WORKER] run_engine returned no socket -- punch failed")
            return
        print("[PUNCH-WORKER] run_engine returned punched socket; "
              "connecting back to reverse server {0}".format(reverse_server_dest),
              flush=True)
        log("[PUNCH-WORKER] run_engine returned punched socket; "
            "connecting back to reverse server {0}".format(reverse_server_dest))

        # Make reverse connect to listen server in main process.
        # Handles passing messages between the punch sock <--> reverse con.
        selector_proxy(punched_sock, reverse_server_dest, stop_reader)
        print("[PUNCH-WORKER] selector_proxy returned; worker exiting", flush=True)
        log("[PUNCH-WORKER] selector_proxy returned; worker exiting")
    except KeyboardInterrupt:
        print("[PUNCH-WORKER] KeyboardInterrupt; exiting silently", flush=True)
        log("[PUNCH-WORKER] KeyboardInterrupt; exiting silently")
    except (OSError, ConnectionError) as e:
        print("[PUNCH-WORKER] OS/Connection error: " + repr(e), flush=True)
        log("[PUNCH-WORKER] OS/Connection error: " + repr(e))
        log_exception()
    except Exception as e:
        print("[PUNCH-WORKER] unexpected exception: " + repr(e), flush=True)
        log("[PUNCH-WORKER] unexpected exception: " + repr(e))
        # Prevent thread or process blow up.
        log_exception()
        raise e


async def start_punching_process(nic: Any, puncher: Any, stop_reader: Any, proc_pool: Optional[Any] = None, node_msg_cb: Optional[Any] = None) -> Optional[Any]:
    """Start the out-of-process punch worker and accept the reverse connection it makes back."""
    log("[PUNCH-PROC] start_punching_process enter af={0} src_ip={1} dest_ip={2} nic={3} node_msg_cb={4}".format(
        getattr(puncher, "af", None),
        getattr(puncher, "src_ip", None),
        getattr(puncher, "dest_ip", None),
        getattr(nic, "name", None),
        node_msg_cb is not None,
    ))
    reverse_server = None
    try:
        # Create a listen server for receiving a connection back from
        # the punching process. The bridge from the punch worker to
        # the main process is ALWAYS same-host -- there is no reason
        # for it to traverse the NIC, and on Windows XP a TCP connect
        # from the NIC IP back to the SAME NIC IP gets refused with
        # WinError 10061 ("connection refused") because XP defaults to
        # the strong host model. Vista+ silently routes same-NIC-to-
        # same-NIC connects through loopback so the bug never showed
        # there. Bind the listener to INADDR_ANY (0.0.0.0 / ::) so the
        # OS accepts connections via loopback regardless of host model;
        # the worker then connects to 127.0.0.1 / ::1 and the bridge
        # works on every Windows version.
        reverse_route = nic.route(puncher.af)
        reverse_route = await reverse_route.bind(ips=puncher.src_ip)

        if puncher.af == 2:  # IP4
            any_addr = "0.0.0.0"
            sock_family = socket.AF_INET
        else:
            any_addr = "::"
            sock_family = socket.AF_INET6

        log("[PUNCH-PROC] creating reverse_server on {0} (loopback bridge)".format(any_addr))
        listener_sock = socket.socket(sock_family, socket.SOCK_STREAM)
        listener_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener_sock.bind((any_addr, 0))
        listener_sock.setblocking(False)
        reverse_server = await Pipe(
            TCP, None, reverse_route, sock=listener_sock,
        ).connect()
        if reverse_server is None:
            log("[PUNCH-PROC] reverse_server bind/connect returned None; aborting")
            try:
                listener_sock.close()
            except OSError:
                pass
            return None

        # Pre-populate the reverse_server's pipe_events.msg_cbs with the
        # node-level dispatcher BEFORE awaiting accept. Without this, the
        # punch worker's bridged connection arrives at TCPClientProtocol,
        # which copies pipe_events.msg_cbs (empty) into the new
        # client_events.msg_cbs, then immediately receives the peer's
        # ECHO bytes and drops them with "No msg cbs registered". The
        # on_plugin_done attach happens AFTER set_result fires, well
        # after the first inbound byte. Pre-populating means the
        # inheritance copies a non-empty list at connection_made time.
        if node_msg_cb is not None and getattr(reverse_server, "pipe_events", None) is not None:
            pe = reverse_server.pipe_events
            before = len(pe.msg_cbs)
            pe.msg_cbs.add(node_msg_cb)
            if len(pe.msg_cbs) != before:
                log("[PUNCH-PROC] pre-populated reverse_server.pipe_events.msg_cbs "
                    "with node_msg_cb (count={0})".format(len(pe.msg_cbs)))

        # The bridge from the punch worker to the main process is
        # ALWAYS same-host. We saw a flaky `WinError 10061 (connection
        # refused)` on XP when the worker connected to its own NIC IP;
        # other XP-as-connector pairs in the same sweep didn't trip
        # it, so it's not a deterministic strict-host-model issue,
        # but routing the bridge through loopback removes that whole
        # class of host-model / NIC-routing risk regardless. The
        # listener above is bound to INADDR_ANY so loopback connects
        # land on it; the worker connects to 127.0.0.1 / ::1.
        reverse_port = reverse_server.sock.getsockname()[1]
        if puncher.af == 2:  # IP4
            reverse_server_dest = ("127.0.0.1", reverse_port)
        else:
            reverse_server_dest = ("::1", reverse_port)
        log("[PUNCH-PROC] reverse_server listening on {0}:{1}; "
            "worker will bridge via loopback {2}:{1}".format(
                any_addr, reverse_port, reverse_server_dest[0],
            ))

        # Start the punching in a new process.
        # Store the future so the caller can inspect / cancel it if needed.
        loop = asyncio.get_event_loop()
        args = (puncher, reverse_server_dest, stop_reader)
        print("[PUNCH-PROC] dispatching worker via run_in_executor "
              "(proc_pool={0}) reverse_dest={1}".format(
                  type(proc_pool).__name__ if proc_pool else "None",
                  reverse_server_dest,
              ), flush=True)
        log("[PUNCH-PROC] dispatching punching_process via run_in_executor "
            "(proc_pool={0})".format(type(proc_pool).__name__ if proc_pool else "None"))
        worker_fut = loop.run_in_executor(proc_pool, punching_process, *args)

        def worker_done(fut):
            """Forward punching_process exceptions to the host process log."""
            try:
                exc = fut.exception()
            except (asyncio.CancelledError, Exception):  # pylint: disable=broad-except
                exc = None
            if exc is not None:
                print("[PUNCH-PROC] worker future raised {0}: {1}".format(
                    type(exc).__name__, repr(exc),
                ), flush=True)
                log("[PUNCH-PROC] worker future raised {0}: {1}".format(
                    type(exc).__name__, repr(exc),
                ))
            else:
                print("[PUNCH-PROC] worker future completed cleanly", flush=True)
                log("[PUNCH-PROC] worker future completed cleanly")

        worker_fut.add_done_callback(worker_done)

        # The punch process makes a new connection to the
        # reverse connect server which we accept to connect the processes.
        # Timeout sized for two-bucket dual-fire worst case: primary
        # rendezvous wait can be up to WINDOW + max_clock_error (62s
        # in FAST_PUNCH_PARAMS), then if the primary misses we wait
        # another WINDOW (42s) for the secondary, plus engine fire/
        # monitor (~6s).  Total worst case ~110s; 130s leaves headroom
        # for setup overhead.  Was 60s when there was only a single
        # fire, which silently truncated the secondary attempt.
        print("[PUNCH-PROC] awaiting reverse_server.accept (130s)", flush=True)
        log("[PUNCH-PROC] awaiting reverse_server.accept (130s)")
        punch_process_connection = await asyncio.wait_for(
            reverse_server.accept(), timeout=130
        )
        print("[PUNCH-PROC] reverse_server.accept returned conn={0}".format(
            punch_process_connection is not None,
        ), flush=True)
        log("[PUNCH-PROC] reverse_server.accept returned conn={0}".format(
            punch_process_connection is not None,
        ))

        return punch_process_connection
    except (asyncio.TimeoutError, asyncio.CancelledError) as e:
        print("[PUNCH-PROC] reverse_server.accept timed out or cancelled: " + repr(e), flush=True)
        log("[PUNCH-PROC] start_punching_process timed out or cancelled: " + repr(e))
    except (OSError, ConnectionError) as e:
        print("[PUNCH-PROC] OS/Connection error: " + repr(e), flush=True)
        log("[PUNCH-PROC] start_punching_process OS/Connection error: " + repr(e))
        log_exception()
    finally:
        print("[PUNCH-PROC] cleanup", flush=True)
        log("[PUNCH-PROC] start_punching_process exiting (cleanup)")
        if reverse_server is not None:
            await async_wrap_errors(reverse_server.close(keep_clients=True))
