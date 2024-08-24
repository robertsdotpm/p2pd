import warnings
from .ip_range import *
from .nat import *
from .interface import *
from .nat_rewrite import *

INITIATED_PREDICTIONS = 1
RECEIVED_PREDICTIONS = 2
UPDATED_PREDICTIONS = 3
INITIATOR = 1
RECIPIENT = 2

# Number of seconds in the future from an NTP time
# for hole punching to occur.
NTP_MEET_STEP = 5

# Fine tune various network settings.
PUNCH_CONF = dict_child({
    # Reuse address tuple for bind() socket call.
    "reuse_addr": True,

    # Return the sock instead of the base proto.
    #"sock_only": True,

    # Disable closing sock on error
    # Applies to the pipe_open only (may not be needed.)
    "do_close": False,
}, NET_CONF)

"""
The function bellow is used to adjust sleep parameters
for the punching algorithm. Sleep time is reduced
based on how close the destination is.
"""
def get_punch_mode(af, dest_ip, same_machine):
    cidr = af_to_cidr(af)
    dest_ipr = IPRange(dest_ip, cidr=cidr)

    # Calculate punch mode
    if dest_ipr.is_public:
        return TCP_PUNCH_REMOTE
    else:
        if same_machine:
            return TCP_PUNCH_SELF
        else:
            return TCP_PUNCH_LAN

def tcp_puncher_states(dest_mappings, state):
    # bool of dest_mappings, start state, to state.
    progressions = [
        [False, None, INITIATED_PREDICTIONS],
        [True, None, RECEIVED_PREDICTIONS],
        [True, INITIATED_PREDICTIONS, UPDATED_PREDICTIONS]
    ]

    # What protocol 'side' corresponds to a state.
    sides = {
        INITIATED_PREDICTIONS: INITIATOR,
        UPDATED_PREDICTIONS: INITIATOR,
        RECEIVED_PREDICTIONS: RECIPIENT,
    }

    # Progress the state machine.
    for progression in progressions:
        from_recv, from_state, to_state = progression
        if from_recv != bool(dest_mappings):
            continue

        if from_state != state:
            continue

        return (to_state, sides[to_state])
    
    raise Exception("Invalid puncher state progression.")

"""
We can keep trying until success without the mappings
changing. However, unpredictable nats that use
delta N will be timing sensitive. If timing info
is available the protocol should try use that.
"""
async def delayed_punch(af, ms_delay, mapping, dest, loop, interface, conf=PUNCH_CONF):
    try:
        """
        Schedule connection to run across time.

        How long it takes the event loop to start a
        routine is outside of our control. This
        code adjusts the delay based on any amount
        of time already passed.
        """
        if ms_delay:
            await asyncio.sleep(ms_delay / 1000)

        # Bind to a specific port and interface.
        route = await interface.route(af).bind(
            mapping.local
        )

        # Open connection -- return only sock.
        sock = await socket_factory(
            route=route,
            dest_addr=dest, 
            conf=conf
        )

        # Requires this special sock option:
        reuse_set = sock.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR
        )

        # Sanity check for the sock option.
        if not reuse_set:
            log("Punch socket missing reuse addr opt.")
            return
        
        # Require a non-blocking socket.
        if sock.getblocking():
            log("Punch sock is blocking.")
            return

        # Async connect that sends SYN.
        await loop.sock_connect(
            sock,
            dest.tup
        )

        # Failure.
        # We strip None responses out.
        if sock is None:
            return None

        """
        At some point I expect errors to be made if a
        local IP + local port is reused for the same
        dest IP + dest port and it successfully gets
        connected. So successive calls might fail.
        """
        mapping.sock = sock
        return mapping
    except:
        return None
    
"""
Smarter code that is less spammy used for remote
punching. Won't overwhelm the event loop like the
above code will. Takes advantage of the massive timeouts
in the Internet as packets travel across routers.
Optimized and tested for remote connections.
"""
async def schedule_delayed_punching(af, dest_addr, send_mappings, recv_mappings, interface):
    print("in schedule delay punch")
    #print(f"{len(send_mappings)} {dest_addr} {recv_mappings[0].remote}")

    # Config.
    secs = 6
    ms_spacing = 5

    # Create punching async task list.
    tasks = []
    steps = int((secs * 1000) / ms_spacing)
    route = interface.route(af)

    assert(steps > 0)
    assert(steps)
    assert(len(send_mappings))


    for i in range(0, len(send_mappings)):
        # Endpoint to punch to.
        dest = await Address(
            dest_addr,
            recv_mappings[i].remote,
            route
        ).res()

        # Attempt to punch dest at intervals.
        for sleep_time in range(0, steps):
            tasks.append(
                asyncio.wait_for(
                    delayed_punch(
                        # Address family for the con.
                        af,

                        # Wait until ms to do punching.
                        # Punches are split up over time
                        # to increase chances of success.
                        sleep_time * ms_spacing,

                        # Local mapping.
                        send_mappings[i],

                        # Destination addr to connect to.
                        dest,

                        # Event loop for this process.
                        asyncio.get_event_loop(),

                        # Punch from this interface.
                        interface,
                    ),
                    2
                )
            )
    
    # Start running tasks.
    assert(len(tasks))
    all_tasks = asyncio.gather(
        *tasks,
        return_exceptions=False
    )
    outs = await all_tasks
    outs = strip_none(outs)
    return outs

async def wait_for_punch_time(current_ntp, ntp_meet):
    # Sleep until the ntp timeframe.
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

def choose_same_punch_sock(our_wan, outs):
    chosen_sock = None
    try:
        our_ip_num = ip_str_to_int(our_wan)
        h_val = 0
        for mapping in outs:
            sock = mapping.sock
            remote_port = mapping.remote
            their_ip_host, their_r_port = sock.getpeername()
            their_ip_num = ip_str_to_int(
                their_ip_host
            )

            """
            A TCP connection is defined by a unique tuple of
            src_ip, src_port, dest_ip, dest_port. The purpose
            of this code is to define a single view of the
            'highest' value connection based on the tuple.
            The highest connection will be used in the event
            multiple 'holes' were punched. The clients will
            close the unneeded connections.
            """
            if our_ip_num == their_ip_num:
                x = sorted([our_ip_num, their_ip_num, remote_port, their_r_port])
            else:
                if our_ip_num > their_ip_num:
                    x = [our_ip_num, their_ip_num, remote_port, their_r_port]
                else:
                    x = [their_ip_num, our_ip_num, their_r_port, remote_port]

            # Mix values into a somewhat unique result.
            h = abs(hash(str(x)))
            assert(h > 0)
            if h > h_val:
                h_val = h
                chosen_sock = sock
    except Exception as e:
        log_exception()
        log("unknown exception occured")

    return chosen_sock

def close_unneeded_socks(needed, outs):
    for mapping in outs:
        if mapping.sock is None:
            continue

        if mapping.sock != needed:
            mapping.sock.close()

async def do_punching(af, dest_addr, send_mappings, recv_mappings, current_ntp, ntp_meet, mode, interface):
    """
    Punching is done in its own process.
    The process returns an open socket and Python
    warns that the socket wasn't closed properly.
    This is the intention and not a bug!
    This code disables that warning.
    """
    warnings.filterwarnings('ignore', message="unclosed", category=ResourceWarning)

    """
    Any patched interface stuff won't work because it
    gets pickled and unpickled into a dict and reloaded
    into the standard interface class.
    """
    interface = await select_if_by_dest(
        af,
        dest_addr,
        interface
    )

    # Set our WAN address from default route.
    our_wan = interface.route(af).ext()

    # Wait for NTP punching time.
    if ntp_meet:
        await wait_for_punch_time(current_ntp, ntp_meet)

    """
    If punching to our self or a machine on the LAN
    then the ir remote port doesn't apply. Punch to
    their local port instead.
    """
    if mode in [TCP_PUNCH_SELF, TCP_PUNCH_LAN]:
        for mapping in recv_mappings:
            mapping.remote = mapping.local

    # Carry out TCP punching.
    outs = await schedule_delayed_punching(
        af=af,
        dest_addr=dest_addr,
        send_mappings=send_mappings,
        recv_mappings=recv_mappings,
        interface=interface,
    )

    print("punch outs = ")
    print(outs)

    # Make both sides choose the same socket.
    chosen_sock = choose_same_punch_sock(our_wan, outs)
    if chosen_sock is None:
        log("> tcp punch chosen sock is none")
        return None

    # Close all other sockets that aren't needed.
    close_unneeded_socks(chosen_sock, outs)

    print(f"chosen sock = {chosen_sock}")
    
    # Return sock result.
    return chosen_sock


