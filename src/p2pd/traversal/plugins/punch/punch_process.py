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
from multiprocessing.reduction import send_handle, recv_handle
import os
import asyncio
from ....nic.nat.nat_predict import *
from .utility.punch_utils import *
from .punch_defs import *
from ....utility.clock_skew import *
from ....net.asyncio.event_loop import *
from ....net.pipe.pipe import *
from ....node.node_defs import *
from .engines.tcp_selector_simple.engine import *
from ....net.selector_proxy import selector_proxy

"""
Punching is done in its own process.
The process returns an open socket and Python
warns that the socket wasn't closed properly.
This is the intention and not a bug!
This code disables that warning.
"""
def punching_process_entry(puncher, listen_tup):
    print("punching proc entry")
    punched_sock = puncher.run_engine(tcp_selector_punch_engine)
    selector_proxy(punched_sock, listen_tup)

async def start_punching_process(nic, puncher, proc_pool=None):
    try:
        print("start punching proc entry")
        route = await nic.route(puncher.af)
        listen_pipe = await Pipe(TCP, None, route).connect()
        listen_tup = (route.nic(), listen_pipe.sock.getsockname()[1])
        args = (puncher, listen_tup,)

        # Start the punching process in a thread.
        loop = asyncio.get_event_loop()
        future = loop.run_in_executor(
            proc_pool, 
            punching_process_entry,
            args
        )

        # Get client pipe from listen server.
        listen_client_pipe = await listen_pipe.pipe_events # <--- accept()

        # Close original listen server.
        # Client pipe is still connected so this is fine.
        await listen_pipe.close()

        print("return pipe = ", listen_client_pipe)
        #pipe = sock_to_pipe(sock, nic)
        return listen_client_pipe
    except Exception as e:
        log_exception()
        print("error in start_punching_process:", e)
        raise

async def workspace():
    return
    _, proc_pool = await get_pp_executors()
    future = await start_punching_process(args=(), proc_pool=proc_pool)
    print(future)

if __name__ == "__main__":
    async_run(workspace())