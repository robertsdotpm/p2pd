import warnings
from ....nic.interface import *
from .punch_defs import *
from .punch_utils import *
from .punch_scheduling import *

async def wait_for_punch_time(current_ntp, ntp_meet):
    # Sleep until the ntp timeframe.
    assert(current_ntp)
    if current_ntp < ntp_meet:
        remaining_time = float(ntp_meet - current_ntp)
        if remaining_time:
            log(
                "> punch waiting for meeting = %s" %
                (str(remaining_time))
            )

            await asyncio.sleep(remaining_time)
    else:
        log("TCP punch behind current meeting time!")

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
        Log.log_p2p(msg, node_id)

        # Punched hole to the remote node.
        route = await interface.route(af).bind(sock.getsockname()[1])
        upstream_dest = sock.getpeername()[:2]
        upstream_pipe = await pipe_open(
            route=route,
            proto=TCP,
            dest=upstream_dest,
            sock=sock,
            msg_cb=punch_close_msg
        )

        # Reverse connect to a listen server in parent process.
        # This avoids sharing between processes which breaks easily.
        route = await interface.route(af).bind()
        client_pipe = await pipe_open(
            proto=TCP,
            dest=reverse_tup,
            route=route,
            msg_cb=punch_close_msg
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
        while 1:
            await asyncio.sleep(1)

            # Exit loop if chain breaks.
            if False in [client_pipe.is_running, upstream_pipe.is_running]:
                break
                
        # Ensure cleanup for pipes.
        await client_pipe.close()
        await upstream_pipe.close()
    except:
        log_exception()