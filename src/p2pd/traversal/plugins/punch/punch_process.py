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
def punching_process_entry(child_con):
    print("punching proc entry")
    try:
        #puncher, child_con = args
        print(child_con)

        #sock = puncher.run_engine(tcp_selector_punch_engine)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("about to send handle ", os.getppid(), " fd ", sock.fileno())
        if sock:
            send_handle(child_con, sock.fileno(), os.getppid())
            sock.close()
    except:
        what_exception()

async def recv_handle_async(parent_con, proc_pool=None, timeout=None):
    loop = asyncio.get_event_loop()
    
    # Run the blocking call in a thread
    fut = loop.run_in_executor(proc_pool, recv_handle, parent_con)
    
    try:
        fd = await asyncio.wait_for(fut, timeout=timeout)
        return fd
    except asyncio.TimeoutError:
        # handle timeout: maybe return None or raise
        return None

async def start_punching_process(nic, puncher, proc_pool=None):
    try:
        print("start punching proc entry")
        parent_con, child_con = mp.Pipe() # can old platforms not serialise child_con?
        args = (puncher, child_con,)
        args = (child_con,) 
        #args = (1,)
        print("punch args ", args)
        print("proc pool = ", proc_pool)

        # Schedule TCP punching in process pool executor.
        p = mp.Process(target=punching_process_entry, args=args)
        p.start()

        """
        loop = asyncio.get_event_loop()
        future = loop.run_in_executor(
            proc_pool, # Disable proc exe for now
            punching_process_entry,
            args
        )
        """

        #print("before run exec")
        #await asyncio.wait_for(future, timeout=20) # TODO
        print("after run exec")
        fd = recv_handle(parent_con)


        #fd = await recv_handle_async(parent_con, timeout=5)
        if fd is None:
            raise Exception("recv_handle timed out")
        else:
            print("got FD", fd)

        sock = socket.socket(fileno=fd)
        print("punched sock = ", sock)

        # Wrap socket in pipe and return it (todo: set node message handler stuff.)
        nic_port = sock.getsockname()[1]
        route = await nic.route(puncher.af).bind(port=nic_port)
        pipe = await Pipe(
            TCP, 
            sock.getpeername()[:2], 
            route, 
            sock=sock
        ).connect()
        print("return pipe = ", pipe)
        return pipe
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