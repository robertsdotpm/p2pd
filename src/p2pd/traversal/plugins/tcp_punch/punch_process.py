import asyncio
from ....nic.nat.nat_predict import *
from .punch_utils import *
from .punch_defs import *
from ....utility.clock_skew import *
from ....net.asyncio.event_loop import *
from .start_punching import start_punching
from ....net.pipe.pipe import *
from ....node.node_defs import *
from ....net.asyncio.async_run import *

async def do_punching_wrapper(af, dest_addr, send_mappings, recv_mappings, current_ntp, ntp_meet, mode, interface, reverse_tup, node_id):
    has_success = asyncio.Event()
    task = asyncio.create_task(
        async_wrap_errors(
            start_punching(
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

    while not shutdown_event.is_set():
        await asyncio.sleep(1)

# Started in a new process.
def proc_do_punching(args):
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
        return async_run(
            async_wrap_errors(
                do_punching_wrapper(
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
        )
    except Exception:
        log_exception()

async def setup_punching_process(client, puncher_class):
    # Listen server that process will connect back to.
    # References are saved to avoid garbage collection.
    route = await client.interface.route(client.af).bind()
    client.listen_pipe = await Pipe(TCP, None, route).connect(client.node.msg_cb)
    
    # Might not be necessary since the get addr infos does this.
    """
    interface = await select_if_by_dest(
        self.af,
        self.dest_info["ip"],
        self.interface
    )
    """
    interface = client.interface

    # Passed on to a new process.
    listen_tup = client.listen_pipe.sock.getsockname()[:2]
    args = (
        puncher_class,
        listen_tup,
        client.to_dict(),
        interface,
        client.node.node_id[:8]
    )

    try:
        # Schedule TCP punching in process pool executor.
        loop = asyncio.get_event_loop()
        if not client.pp_executor:
            puncher_future = loop.run_in_executor(
                client.pp_executor,
                proc_do_punching,
                args
            )
        else:
            log("Trying new punching code for proc_do_punching.")
            puncher_future = client.pp_executor.submit(
                proc_do_punching, 
                args
            )
        
        # Check every 100 ms for 5 seconds.
        while not shutdown_event.is_set():
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