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


# Started in a new process.
"""
Punching is done in its own process.
The process returns an open socket and Python
warns that the socket wasn't closed properly.
This is the intention and not a bug!
This code disables that warning.
"""
def punching_process_entry(args):
    child_con = args[-1]
    puncher = args[0]
    socks = puncher.run_engine(tcp_selector_punch_engine)
    





    send_handle(child_con, s.fileno(), os.getppid())

    # close worker copy
    s.close()

    print("proc entry")
    return
    try:
        """
        On Windows it seems like using the default 'proactor event loop'
        prevents the TCP hole punching code from working. It seems that
        manually setting the event loop to use SelectorEventLoop
        fixes the issue. However, this may mean breaking some of
        my command execution code on Windows -- test this.
        """
        loop = CustomEventLoop()
        asyncio.set_event_loop(loop)

        # Build a puncher from a dictionary.
        puncher_class = args[0]
        reverse_tup = args[1]
        d = args[2]
        interface = args[3]
        node_id = args[4]
        puncher = puncher_class.from_dict(d)

        async def wrapper():
            has_success = asyncio.Event()
            task = create_task(
                async_wrap_errors(
                    do_punching(
                        af,
                        dest_addr,
                        send_mappings,
                        recv_mappings,
                        current_ntp,
                        ntp_meet,
                        mode,
                        interface,
                        reverse_tup,
                        has_success,
                        node_id,
                    )
                )
            )

            """
            The punching func has 30 seconds to set this.
            If it doesn't a timeout error is thrown to end the process.
            So a hung punching process doesn't take up a process.
            On the other hand -- if it succeeds and sets it block forever.
            """
            await asyncio.wait_for(
                has_success.wait(),
                30
            )

            while 1:
                await asyncio.sleep(1)

        # Allow more recent Pythons to do punching.
        if hasattr(asyncio, "run"):
            f = async_wrap_errors(
                wrapper(
                    puncher.af,
                    puncher.dest_info["ip"],
                    puncher.send_mappings,
                    puncher.recv_mappings,
                    puncher.sys_clock.time(),
                    puncher.start_time,
                    puncher.punch_mode,
                    interface,
                    reverse_tup,
                    node_id
                )
            )

            # Start a  new event loop and run the coroutine.
            return asyncio.run(f)
        else:
            # Use older deprecated functions.
            loop = asyncio.get_event_loop()
            f = create_task(
                async_wrap_errors(
                    wrapper(
                        puncher.af,
                        puncher.dest_info["ip"],
                        puncher.send_mappings,
                        puncher.recv_mappings,
                        puncher.sys_clock.time(),
                        puncher.start_time,
                        puncher.punch_mode,
                        interface,
                        reverse_tup,
                        node_id
                    )
                ),
                loop=loop
            )

            # Workers better for older Python versions.
            return loop.run_until_complete(f)
    except Exception:
        log_exception()

async def start_punching_process(args, f_target=punching_process_entry, proc_pool=None):
    parent_con, child_con = mp.Pipe()
    args += (child_con,)

    # Schedule TCP punching in process pool executor.
    loop = asyncio.get_event_loop()
    future = loop.run_in_executor(
        proc_pool,
        f_target,
        args
    )

    #await future
    fd = recv_handle(parent_con)
    s = socket.socket(fileno=fd)
    print(s)


    print("hello world.")
    return
    # Passed on to a new process.

    args = (
        puncher_class,
        client.to_dict(),
        interface,
        client.node.node_id[:8]
    )

    try:
        # Check every 100 ms for 5 seconds.
        while not shut_down.is_set():
            try:
                # Check if reverse connect server has a client yet.
                if len(client.listen_pipe.tcp_clients):
                    # Reverse connect from punching process to
                    # server in the main thread.
                    client.pipe = client.listen_pipe.tcp_clients[0]

                    # Patch close to send close message.
                    pipe_close = client.pipe.close
                    async def close_patch():
                        await client.pipe.send(PUNCH_END)
                        await pipe_close()

                    client.pipe.close = close_patch

                    # Indicate hole made to waiter.
                    client.node.pipe_ready(client.pipe_id, client.pipe)
                    return client.pipe
            except Exception:
                log_exception()
            
            # Check every 100 ms.
            await asyncio.sleep(0.1)

            # Puncher ended.
            if puncher_future.done():
                client.active_punchers = max(
                    0,
                    client.active_punchers - 1
                )

                return
    except Exception:
        log_exception()



async def workspace():
    _, proc_pool = await get_pp_executors()
    future = await spawn_punching_process(args=(), proc_pool=proc_pool)
    print(future)

if __name__ == "__main__":
    async_run(workspace())