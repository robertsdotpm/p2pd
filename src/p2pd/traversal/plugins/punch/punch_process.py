"""
The current design doesn't make sense.
The code returns a socket from a process but creates a listen server because 
to route to that process. its easier to pass the socket using send / recv handle


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

"""
Punching is done in its own process.
The process returns an open socket and Python
warns that the socket wasn't closed properly.
This is the intention and not a bug!
This code disables that warning.
"""
def punching_process_entry(args):
    puncher, child_con = args
    sock = puncher.run_engine(tcp_selector_punch_engine)
    send_handle(child_con, sock.fileno(), os.getppid())
    sock.close()

async def start_punching_process(nic, puncher, proc_pool=None):
    parent_con, child_con = mp.Pipe()
    args = (puncher, child_con,)

    # Schedule TCP punching in process pool executor.
    loop = asyncio.get_event_loop()
    future = loop.run_in_executor(
        proc_pool,
        punching_process_entry,
        args
    )

    #await future.
    await future
    fd = recv_handle(parent_con)
    sock = socket.socket(fileno=fd)
    print("punched sock = ", sock)

    # Wrap socket in pipe and return it (todo: set node message handler stuff.)
    nic_ip = sock.getsockname()[1]
    route = await nic.route(puncher.af).bind(nic_ip)
    return await Pipe(
        TCP, 
        sock.getpeername()[:2], 
        route, 
        sock=sock
    ).connect()

async def workspace():
    return
    _, proc_pool = await get_pp_executors()
    future = await start_punching_process(args=(), proc_pool=proc_pool)
    print(future)

if __name__ == "__main__":
    async_run(workspace())