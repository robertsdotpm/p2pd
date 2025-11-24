import asyncio
from .....nic.nat.nat_predict import *
from .utility.punch_utils import *
from .punch_defs import *
from .....utility.clock_skew import *
from .....net.asyncio.event_loop import *
from .start_punching import start_punching
from .....net.pipe.pipe import *
from .....node.node_defs import *

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

        # Allow more recent Pythons to do punching.
        if hasattr(asyncio, "run"):
            f = async_wrap_errors(
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

            # Start a  new event loop and run the coroutine.
            return asyncio.run(f)
        else:
            # Use older deprecated functions.
            loop = asyncio.get_event_loop()
            f = create_task(
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
                ),
                loop=loop
            )

            # Workers better for older Python versions.
            return loop.run_until_complete(f)
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
        puncher_future = loop.run_in_executor(
            client.pp_executor,
            proc_do_punching,
            args
        )
        
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

async def start_punching(af, dest_addr, send_mappings, recv_mappings, current_ntp, ntp_meet, mode, interface, reverse_tup, has_success, node_id):
    try:
        """
        Punching is done in its own process.
        The process returns an open socket and Python
        warns that the socket wasn't closed properly.
        This is the intention and not a bug!
        This code disables that warning.
        """
        warnings.filterwarnings('ignore', message="unclosed", category=ResourceWarning)

        # Set our WAN address from default route.
        our_wan = interface.route(af).ext()

        # Wait for NTP punching time.
        if ntp_meet:
            assert(current_ntp)
            await wait_for_punch_time(current_ntp, ntp_meet)
        else:
            log_exception("ntp meet time is 0!")


        """
        If punching to our self or a machine on the LAN
        then the ir remote port doesn't apply. Punch to
        their local port instead.
        """
        if mode == TCP_PUNCH_LAN:
            for mapping in recv_mappings:
                mapping.remote = mapping.local

        # Log warning messages.
        punching_sanity_check(
            mode=mode,
            our_wan=our_wan,
            dest_addr=dest_addr,
            send_mappings=send_mappings,
            recv_mappings=recv_mappings,
        )

        #print(interface)
        #print("schedule delayed punching", 
        #send_mappings, recv_mappings)

        # Carry out TCP punching.
        outs = await schedule_delayed_punching(
            af=af,
            dest_addr=dest_addr,
            send_mappings=send_mappings,
            recv_mappings=recv_mappings,
            interface=interface,
        )

        # Make both sides choose the same socket.
        sock = choose_same_punch_sock(our_wan, outs)
        if sock is None:
            log("> tcp punch chosen sock is none")
            return None
        
        # Log punch upstream.
        local_tup = sock.getsockname()[:2]
        remote_tup = sock.getpeername()[:2]
        msg = fstr("<punch> Upstream {0} = {1}", (local_tup, remote_tup,))
        msg += fstr(" on '{0}'", (interface.name,))
        log_p2p(msg, node_id)

        # Punched hole to the remote node.
        route = await interface.route(af).bind(sock.getsockname()[1])
        upstream_dest = sock.getpeername()[:2]
        upstream_pipe = await Pipe(TCP, upstream_dest, route, sock=sock).connect(
            punch_close_msg
        )

        # Reverse connect to a listen server in parent process.
        # This avoids sharing between processes which breaks easily.
        route = await interface.route(af).bind()
        client_pipe = await Pipe(TCP, reverse_tup, route).connect(
            punch_close_msg
        )

        async def forward_to_client_pipe(msg, client_tup, pipe):
            await client_pipe.send(msg, client_pipe.sock.getpeername())

        async def forward_to_upstream_pipe(msg, client_tup, pipe):
            await upstream_pipe.send(msg, upstream_pipe.sock.getpeername())

        upstream_pipe.add_msg_cb(forward_to_client_pipe)
        client_pipe.add_msg_cb(forward_to_upstream_pipe)
        upstream_pipe.unsubscribe(SUB_ALL)
        client_pipe.unsubscribe(SUB_ALL)

        # Prevent this process from exiting.
        has_success.set()
        while not shut_down.is_set():
            await asyncio.sleep(1)

            # Exit loop if chain breaks.
            if False in [client_pipe.is_running, upstream_pipe.is_running]:
                break
                
        # Ensure cleanup for pipes.
        await client_pipe.close()
        await upstream_pipe.close()
    except Exception:
        log_exception()