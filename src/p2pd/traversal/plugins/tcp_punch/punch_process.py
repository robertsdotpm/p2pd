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
"""

from typing import Any, Optional
import asyncio
import signal
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
        log("[PUNCH-WORKER] calling run_engine")
        punched_sock = puncher.run_engine(tcp_selector_punch_engine)
        if not punched_sock:
            log("[PUNCH-WORKER] run_engine returned no socket -- punch failed")
            return
        log("[PUNCH-WORKER] run_engine returned punched socket; "
            "connecting back to reverse server {0}".format(reverse_server_dest))

        # Make reverse connect to listen server in main process.
        # Handles passing messages between the punch sock <--> reverse con.
        selector_proxy(punched_sock, reverse_server_dest, stop_reader)
        log("[PUNCH-WORKER] selector_proxy returned; worker exiting")
    except KeyboardInterrupt:
        # On Windows, sometimes the signal still gets through.
        # Catching it here ensures the worker dies silently.
        log("[PUNCH-WORKER] KeyboardInterrupt; exiting silently")
    except (OSError, ConnectionError) as e:
        log("[PUNCH-WORKER] OS/Connection error: " + repr(e))
        log_exception()
    except Exception as e:
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
        # the punching process. Listener binds to the NIC IP and the
        # worker connects back to that same NIC IP -- no loopback
        # detour. An earlier version routed this through 127.0.0.1
        # to dodge a hypothesised XP strong-host-model issue, but in
        # practice every other XP-as-connector pair worked fine over
        # the NIC, and the real culprits for the v4 punch flakes were
        # elsewhere (msg_cbs wireup race, plugin timeout, --cmd menu
        # loop, menu wait_for=40 etc). Loopback was load-bearing for
        # nothing; the NIC bind is what the rest of the code expects.
        reverse_route = nic.route(puncher.af)
        reverse_route = await reverse_route.bind(ips=puncher.src_ip)

        log("[PUNCH-PROC] creating reverse_server on src_ip={0} (NIC bind)".format(
            puncher.src_ip,
        ))
        reverse_server = await Pipe(TCP, None, reverse_route).connect()
        if reverse_server is None:
            log("[PUNCH-PROC] reverse_server bind/connect returned None; aborting")
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

        reverse_port = reverse_server.sock.getsockname()[1]
        reverse_server_dest = (puncher.src_ip, reverse_port)
        log("[PUNCH-PROC] reverse_server listening on {0}:{1}".format(
            puncher.src_ip, reverse_port,
        ))

        # Start the punching in a new process.
        # Store the future so the caller can inspect / cancel it if needed.
        loop = asyncio.get_event_loop()
        args = (puncher, reverse_server_dest, stop_reader)
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
                log("[PUNCH-PROC] worker future raised {0}: {1}".format(
                    type(exc).__name__, repr(exc),
                ))
            else:
                log("[PUNCH-PROC] worker future completed cleanly")

        worker_fut.add_done_callback(worker_done)

        # The punch process makes a new connection to the
        # reverse connect server which we accept to connect the processes.
        log("[PUNCH-PROC] awaiting reverse_server.accept (60s)")
        punch_process_connection = await asyncio.wait_for(
            reverse_server.accept(), timeout=60
        )
        log("[PUNCH-PROC] reverse_server.accept returned conn={0}".format(
            punch_process_connection is not None,
        ))

        return punch_process_connection
    except (asyncio.TimeoutError, asyncio.CancelledError) as e:
        log("[PUNCH-PROC] start_punching_process timed out or cancelled: " + repr(e))
    except (OSError, ConnectionError) as e:
        log("[PUNCH-PROC] start_punching_process OS/Connection error: " + repr(e))
        log_exception()
    finally:
        # Always close the listen pipe to release the bound port / fd.
        # Keep clients makes sure not to close the accepted clients.
        log("[PUNCH-PROC] start_punching_process exiting (cleanup)")
        if reverse_server is not None:
            await async_wrap_errors(reverse_server.close(keep_clients=True))
