"""
Tricks to pass FDs around processes work well with threading.
But the approach is --not-- reliable for every OS. The best design
so far is just having a reverse connecting back to a listen server
in the main process (like so):

            punch proc         |      main proc
punched sock <--> reverse con <-->  listen socket
"""

import multiprocessing as mp
import socket
import signal
from multiprocessing.reduction import send_handle, recv_handle
import os
import asyncio
from aionetiface import *
from .utility.punch_utils import *
from .punch_defs import *
from ....node.node_defs import *
from .engines.tcp_selector_simple.engine import *
from aionetiface.net.selector_proxy import selector_proxy



"""
Punching is done in its own process.
The process returns an open socket and Python
warns that the socket wasn't closed properly.
This is the intention and not a bug!
This code disables that warning.
"""
def punching_process_entry(puncher, listening_tup, stop_reader):
    try:
        print("punching proc entry")

        # New punched TCP sock to destination.
        punched_sock = puncher.run_engine(tcp_selector_punch_engine)
        if not punched_sock:
            log("Unable to punch hole with tcp puncher engine.")
            return

        # Make reverse connect to listen server in main process.
        # Handles passing messages between the punch sock <--> reverse con.
        selector_proxy(punched_sock, listening_tup, stop_reader)
    except KeyboardInterrupt:
        # On Windows, sometimes the signal still gets through.
        # Catching it here ensures the worker dies silently.
        pass
    except Exception:
        log_exception()

def accept_reverse_connect_from_punching_proc(listen_sock):
    with listen_sock:
        listen_sock.setblocking(1)
        listen_sock.listen(1)
        
        # Accept the connection
        client_socket, _ = listen_sock.accept()
        
        # The listening socket closes automatically 
        # when we exit this block
        return client_socket

async def start_punching_process(nic, puncher, stop_reader, proc_pool=None):
    loop = asyncio.get_event_loop()
    
    try:
        print("start punching proc entry")

        # Start the listen server used for reverse connect.
        """
        listen_sock = socket.socket(puncher.af, socket.SOCK_STREAM)
        listen_any_tup = await binder_async(
            puncher.af, 
            ip=puncher.src_ip, 
            nic_id=puncher.nic_id
        )
        listen_sock.bind(listen_any_tup)
        """

        listen_route = nic.route(puncher.af)
        listen_route = await listen_route.bind(ips=puncher.src_ip)
        listen_pipe = await Pipe(
            TCP, 
            None, 
            listen_route
        ).connect()

        # Start the punching in a new process.
        # Applies rules to make different kinds of IPs work.
        reverse_ip = patch_connect_ip(puncher.af, puncher.src_ip, puncher.nic_id)
        listening_tup = (reverse_ip, listen_pipe.sock.getsockname()[1])
        args = (puncher, listening_tup, stop_reader)
        print("listening tup", listening_tup)
        print("listen reverse sock = ", listen_pipe.sock)
        print("punch proc args = ", args)
        print("proc pool = ", proc_pool)
        print("before run in ex")

        #with proc_pool as executor:
        
        try:
            loop.run_in_executor(proc_pool, punching_process_entry, *args)
        except asyncio.CancelledError:
            print("\nMain task cancelled, shutting down executor...")
            # The 'with' block will automatically call executor.shutdown(wait=True)
        

        print("after run in exec")

        # Wait for the reverse connect client sock on the listen server.
        # Note: this uses threads and not processes.
        #client_sock = accept_reverse_connect_from_punching_proc(listen_sock)

        """
        client_sock = None
        try:
            client_sock = await asyncio.wait_for(
                loop.run_in_executor(
                    None, # Uses threads!
                    accept_reverse_connect_from_punching_proc,
                    listen_sock
                ),
                timeout=40
            )
        except (asyncio.TimeoutError, asyncio.CancelledError):
            log("Client pipe from accept reverse cancel or timeout")
            if client_sock: 
                client_sock.close()

            return 
        """

        # Wrap client sock in a pipe.
        #client_pipe = await sock_to_pipe(client_sock, nic)
        client_pipe = await asyncio.wait_for(
            listen_pipe.accept(),
            timeout=40
        )
        print("after listen client pipe")
        print("listen client pipe sock = ", client_pipe.sock)
        print("return pipe = ", client_pipe)
        return client_pipe
    except Exception as e:
        log_exception()
        what_exception()
        print("error in start_punching_process:", e)
        #raise

async def workspace():
    return
    _, proc_pool = await get_pp_executors()
    future = await start_punching_process(args=(), proc_pool=proc_pool)
    print(future)

if __name__ == "__main__":
    async_run(workspace())