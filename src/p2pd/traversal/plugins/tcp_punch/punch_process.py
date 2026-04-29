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
from aionetiface import Pipe, TCP, log, log_exception, async_wrap_errors, patch_connect_ip
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
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (OSError, AttributeError, ValueError):
        pass
    try:
        # New punched TCP sock to destination.
        punched_sock = puncher.run_engine(tcp_selector_punch_engine)
        if not punched_sock:
            log("Unable to punch hole with tcp puncher engine.")
            return

        # Make reverse connect to listen server in main process.
        # Handles passing messages between the punch sock <--> reverse con.
        selector_proxy(punched_sock, reverse_server_dest, stop_reader)
    except KeyboardInterrupt:
        # On Windows, sometimes the signal still gets through.
        # Catching it here ensures the worker dies silently.
        pass
    except (OSError, ConnectionError):
        log_exception()
    except Exception as e:
        # Prevent thread or process blow up.
        log_exception()
        raise e


async def start_punching_process(nic: Any, puncher: Any, stop_reader: Any, proc_pool: Optional[Any] = None) -> Optional[Any]:
    """Start the out-of-process punch worker and accept the reverse connection it makes back."""
    reverse_server = None
    try:
        # Create a listen server for receiving a connection
        # back from the punching process.
        reverse_route = nic.route(puncher.af)
        reverse_route = await reverse_route.bind(ips=puncher.src_ip)
        reverse_server = await Pipe(TCP, None, reverse_route).connect()

        # Get the address of the reverse connect server.
        # Applies rules to make different kinds of IPs work.
        reverse_ip = patch_connect_ip(puncher.af, puncher.src_ip, puncher.nic_id)
        reverse_port = reverse_server.sock.getsockname()[1]
        reverse_server_dest = (reverse_ip, reverse_port)

        # Start the punching in a new process.
        # Store the future so the caller can inspect / cancel it if needed.
        loop = asyncio.get_event_loop()
        args = (puncher, reverse_server_dest, stop_reader)
        loop.run_in_executor(proc_pool, punching_process, *args)

        # The punch process makes a new connection to the
        # reverse connect server which we accept to connect the processes.
        punch_process_connection = await asyncio.wait_for(
            reverse_server.accept(), timeout=60
        )

        return punch_process_connection
    except (asyncio.TimeoutError, asyncio.CancelledError) as e:
        log("start_punching_process timed out or cancelled: " + repr(e))
    except (OSError, ConnectionError):
        log_exception()
    finally:
        # Always close the listen pipe to release the bound port / fd.
        # Keep clients makes sure not to close the accepted clients.
        if reverse_server is not None:
            await async_wrap_errors(reverse_server.close(keep_clients=True))
