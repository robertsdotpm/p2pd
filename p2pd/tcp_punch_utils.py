import warnings
from .ip_range import *
from .nat_utils import *
from .interface import *
from .nat_predict import *
from .clock_skew import *
from .keep_alive import set_keep_alive

PUNCH_ALIVE = b"234o2jdjf\n"
PUNCH_END = b"qwekl2k343ok\n"
INITIATED_PREDICTIONS = 1
RECEIVED_PREDICTIONS = 2
UPDATED_PREDICTIONS = 3
INITIATOR = 1
RECIPIENT = 2

# Number of seconds in the future from an NTP time
# for hole punching to occur.
NTP_MEET_STEP = 6

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
        #print(dest.tup)
        if "fe80" == dest.tup[0][:4]:
            route = interface.route(af)
            await route.bind(
                ips=str(route.link_locals[0]),
                port=mapping.local
            )
        else:
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

        # Add pings in the background.
        # This helps the process pool stay clean.
        set_keep_alive(sock)

        # Sanity check for the sock option.
        if not reuse_set:
            log("Punch socket missing reuse addr opt.")
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
        #log_exception()
        return None
    
"""
Smarter code that is less spammy used for remote
punching. Won't overwhelm the event loop like the
above code will. Takes advantage of the massive timeouts
in the Internet as packets travel across routers.
Optimized and tested for remote connections.
"""
async def schedule_delayed_punching(af, dest_addr, send_mappings, recv_mappings, interface):
    try:
        # Config.
        secs = 10
        ms_spacing = 5

        # Create punching async task list.
        tasks = []
        steps = int((secs * 1000) / ms_spacing)

        assert(steps > 0)
        assert(steps)
        assert(len(send_mappings))
        for i in range(0, 1):
            # Validate IP address.
            dest = Address(dest_addr, recv_mappings[i].remote)
            await dest.res(interface.route(af))
            dest = dest.select_ip(af)
            for sleep_time in range(0, steps):
                task = delayed_punch(
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
                )
                tasks.append(task)
                

        # Start running tasks.
        all_tasks = asyncio.gather(*tasks)
        outs = await all_tasks
        outs = strip_none(outs)
        return outs
    except:
        log_exception()

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

def choose_same_punch_sock(our_wan, outs):
    chosen_sock = None
    try:
        our_ip_num = ip_str_to_int(our_wan)
        h_val = 0
        for mapping in outs:
            sock = mapping.sock
            remote_port = mapping.remote
            their_ip_host, their_r_port = sock.getpeername()[:2]
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
            str_to_hash = ""
            socket_quad_list = sorted([our_ip_num, their_ip_num, remote_port, their_r_port])
            for entry in socket_quad_list:
                str_to_hash += f"{entry} "

            # Mix values into a somewhat unique result.
            str_hash = hashlib.sha256(to_b(str_to_hash)).hexdigest()
            str_hash_as_int = int(to_s(str_hash), 16)
            assert(str_hash_as_int > 0)
            if str_hash_as_int > h_val:
                h_val = str_hash_as_int
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

def punching_sanity_check(mode, our_wan, dest_addr, send_mappings, recv_mappings):
    if mode == TCP_PUNCH_SELF:
        for sm in send_mappings:
            for rm in recv_mappings:
                if sm.local == rm.local:
                    error = \
                    f"punch self local port conflict "
                    f"{sm.local} {rm.local}"
                    log(error)

    if mode == TCP_PUNCH_REMOTE:
        if our_wan == dest_addr:
            error = \
            f"punch remote but dest is the same "
            f"as our ext {our_wan}"
            log(error)
            
# Not really the best approach but process communication is a pain.
async def punch_close_msg(msg, client_tup, pipe):
    if msg in PUNCH_END:
        # Allow time to send message down pipes.
        await asyncio.sleep(2)
        await pipe.close()

async def do_punching(af, dest_addr, send_mappings, recv_mappings, current_ntp, ntp_meet, mode, interface, reverse_tup, has_success, node_id):
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
            await wait_for_punch_time(current_ntp, ntp_meet)

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
        msg = f"<punch> Upstream {local_tup} = {remote_tup}"
        msg += f" on '{interface.name}'"
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


async def do_punching_wrapper(af, dest_addr, send_mappings, recv_mappings, current_ntp, ntp_meet, mode, interface, reverse_tup, node_id):
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


def puncher_to_dict(self):
    assert(self.interface)
    assert(self.sys_clock)
    assert(self.state)
    recv_mappings = mappings_objs_to_dicts(self.recv_mappings)
    send_mappings = mappings_objs_to_dicts(self.send_mappings)
    return {
        "af": self.af,
        "src_info": self.src_info,
        "dest_info": self.dest_info,
        "sys_clock": self.sys_clock.to_dict(),
        "start_time": self.start_time,
        "same_machine": self.same_machine,
        "interface": self.interface.to_dict(),
        "punch_mode": self.punch_mode,
        "state": self.state,
        "side": self.side,
        "recv_mappings": recv_mappings,
        "send_mappings": send_mappings,
    }

def puncher_from_dict(d, cls):
    interface = Interface.from_dict(d["interface"])
    recv_mappings = mappings_dicts_to_objs(d["recv_mappings"])
    send_mappings = mappings_dicts_to_objs(d["send_mappings"])
    sys_clock = SysClock.from_dict(d["sys_clock"])
    puncher = cls(
        af=d["af"],
        src_info=d["src_info"],
        dest_info=d["dest_info"],
        stuns=None,
        sys_clock=sys_clock,
        same_machine=d["same_machine"],
        nic=interface
    )
    puncher.state = d["state"]
    puncher.side = d["side"]
    puncher.punch_mode = d["punch_mode"]
    puncher.recv_mappings = recv_mappings
    puncher.send_mappings = send_mappings
    puncher.start_time = Dec(d["start_time"])
    return puncher