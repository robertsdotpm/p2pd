"""
FIN and RST on close:

Something important to note about TCP hole punching: suppose your NAT type is one that reuses mappings under certain conditions. You go ahead and use STUN to setup the mapping and then retrieve what it is. At this point if you were to go ahead and close() the socket used for the STUN transactions it would send out a 'FIN' packet. 

Now, if the router saw that FIN it may decide to close the port mapping. We would hope that multiple outbound connections with the same local tuple to different destinations would mean that a single FIN wouldn't cause the NAT to disregard other packets. But in any cause the STUN connection ought to stay open at least until the TCP punching has been completed.

Synchronicity:

TCP hole punching between two peers heavily depends on synchronized actions.
If a peer sends a SYN too early then they risk having the other side's NAT
send back an RST which will cause the connection to be closed even if the
connection later 'succeeds.' Therefore, writing one of the peers to
'start sooner' than an agreed upon time simply makes their connection unstable.
The correct way to do TCP hole punching is to start at the same time but
synchronicity between networked devices is a notoriously hard problem to solve.

Using the NTP protocol it can be off by between 1 - 50 ms which is significant
enough to matter. The algorithm tries to compensate by sampling and using
statistical methods to remove outliers. The original approach for this was
taken from the Gnuttella code (written in C) and ported to Python.

Wait times:

The protocol is meant to take up to N seconds to complete. Where N is enough
time to receive initial mappings and / or updated mappings + a buffer for
synchronized startup. There is also a limit on the whole process imposed
by the 'pipe waiter' code that waits for a pipe to be returned. If the
limit is too short then you may see connections succeed in the punching
code but then be tore down from the timeout cleanup code. I wanted to
make a note of this here. I am trying to minimize how much time is spent
sleeping so that the process is faster but I am still tweaking this.

Sharing sockets between processes:

The TCP punch module uses Python's ProcessPoolExecutor to spawn child processes
that do the punching operations. Using this design has several benefits. It
means that the timing between peers is slightly more accurate as the main process
is not interrupting the connection code. In reality though: the operating system
still controls scheduling of processes (without using special code to pin the
processes to certain cores.)

Another benefit is that parts of the code which are very 'busy' such as the local
punching algorithm (which essentially just spams connections as much as it can)
will not impact the performance of the main application. There is a consequence
to this design though. If a process exits then presumably the socket descriptors
opened from the process will become unusable. Fortunately, Python's process pool
spins up a list of processes (by default set to the core number) and reuses them.
That means that the sockets should remain valid through the software's lifetime.

Event loops:

On Linux, Mac OS X, BSD... The default event loop is the selector event loop.
On Windows the default event loop is the proactor event loop. When it comes
to running commands and making 'pipes' to processes you need to use the
proactor event loop on Windows. But for TCP hole punching to work the
selector event loop is the only one that seems to make the code work.

When running async code for the first time in an 'executor' / new process
it will need to create a new event loop. Normally this would have quite
a delay. In order to make async code run fast I pre-initialize all executors
with a call to create an event looop. So when async code is run in them
there is no startup penalty. This is important for timing-based code.

Testing:

When it comes to testing punching on the same machine it is necessary to run the punching code in separate processes (with their own event loops.) Otherwise,
they will interfere with each other and the syns won't cross in time. Ideally
each process should be running on its own core with a high priority. But this
is hard to guarantee in practice.

Edge-case: making another connection to the same STUN server, from the same local endpoint due to another TCP punch occuring.
"""

import socket
import multiprocessing
import warnings
import asyncio
from concurrent.futures import ProcessPoolExecutor
from .nat import *
from .ip_range import *
from .stun_client import *
from .clock_skew import *
from .base_stream import *
from .interface import *

#nest_asyncio.apply()
asyncio.set_event_loop_policy(SelectorEventPolicy())

# Config #######################################################
# Number of seconds in the future from an NTP time
# for hole punching to occur.
NTP_MEET_STEP = 3

################################################################
TCP_PUNCH_MAP_NO = 5
TCP_PUNCH_SEND_INITIAL_MAPPINGS = 1
TCP_PUNCH_RECV_INITIAL_MAPPINGS = 2
TCP_PUNCH_UPDATE_RECIPIENT_MAPPINGS = 3
TCP_PUNCH_IN_PROGRESS = 4
TCP_PUNCH_SUCCESS = 5
TCP_PUNCH_FAILURE = 6
PUNCH_INITIATOR = 1
PUNCH_RECIPIENT = 2

# Fine tune various network settings.
PUNCH_CONF = dict_child({
    # Reuse address tuple for bind() socket call.
    "reuse_addr": True,

    # Return the sock instead of the base proto.
    "sock_only": True,

    # Disable closing sock on error.
    "no_close": True,

    # Ref to async event loop func.
    "loop": lambda: selector_event_loop()
}, NET_CONF)

# Just merges two specific lists into slightly different format.
def map_info_to_their_maps(map_info):
    their_maps = []
    for i in range(0, len(map_info["remote"])):
        their_map = [
            map_info["remote"][i],
            map_info["reply"][i],
            map_info["local"][i]
        ]

        their_maps.append(their_map)

    return their_maps

# Started in a new process.
def proc_do_punching(args):
    # Create new event loop and run coroutine in it.
    """
    On Windows it seems like using the default 'proactor event loop'
    prevents the TCP hole punching code from working. It seems that
    manually setting the event loop to use SelectorEventLoop
    fixes the issue. However, this may mean breaking some of
    my command execution code on Windows -- test this.
    """
    asyncio.set_event_loop_policy(SelectorEventPolicy())
    side = args.pop()
    sq = args.pop()
    q = args.pop()

    loop = asyncio.get_event_loop()
    f = asyncio.ensure_future(
        async_wrap_errors(
            TCPPunch.do_punching(side, *args, sq)
        ),
        loop=loop
    )



    f.add_done_callback(lambda t: q.put(t.result()))
    loop.run_until_complete(f)
    #return f.result()


state_info_index = lambda x, y: repr(x) + "@" + str(y)
class TCPPunch():
    def __init__(self, interface, if_list, sys_clock=None, executors=None, queue_manager=None, conf=PUNCH_CONF):
        self.conf = PUNCH_CONF
        self.if_list = if_list
        self.interface = interface
        self.sys_clock = sys_clock
        self.executors = executors
        self.queue_manager = queue_manager
        if self.interface.nat["type"] in BLOCKING_NATS:
            raise Exception("Peer NAT type is unreachable.")

        self.active_no = 0

        # [node_id][pipe_id] = state
        self.state = {}

        # Keep a list of socks used to open TCP mappings
        # to STUN server. If a sock goes out of scope then
        # Pythons garbage collector reaps it and will call
        # close, we want to save it until after a hole punch.
        self.stun_socks = []
        self.sock_queue = queue_manager.Queue()

        # Simple garbage collector for state.
        self.do_state_cleanup = True
        self.tcp_punch_stopped = asyncio.Event()
        self.stop_running = asyncio.Event()
        self.cleanup_task = asyncio.create_task(
            async_wrap_errors(
                self.cleanup_by_timeout()
            )
        )

    async def close(self):
        # Already closed.
        if self.stop_running.is_set():
            return

        self.stop_running.set()
        await self.tcp_punch_stopped.wait()

    def get_punch_mode(self, dest_addr):
        # Loopback so use local punching.
        if dest_addr.is_loopback:
            return TCP_PUNCH_SELF

        # External IP that belongs to ourself.
        # Use local punching.
        needle_ipr = IPRange(dest_addr.tup[0])
        if needle_ipr.is_public:
            # Check all external addresses for routes.
            if ipr_in_interfaces(needle_ipr, self.if_list, mode=IP_PUBLIC):
                return TCP_PUNCH_SELF

            # It's possible to use public IPs for NIC addresses.
            # Check whether it matches any in our routes.
            if ipr_in_interfaces(needle_ipr, self.if_list, mode=IP_PRIVATE):
                return TCP_PUNCH_SELF

        # Private LAN IP so use local punching.
        if dest_addr.is_private:
            # Is this our own NIC address?
            if ipr_in_interfaces(needle_ipr, self.if_list, mode=IP_PRIVATE):
                return TCP_PUNCH_SELF
            else:
                return TCP_PUNCH_LAN

        # Otherwise use remote punching.
        return TCP_PUNCH_REMOTE

    def get_ntp_meet_time(self):
        if self.sys_clock is None:
            return 0

        return self.sys_clock.time() + Dec(NTP_MEET_STEP)

    def get_state_info(self, node_id, pipe_id):
        if node_id not in self.state:
            return None

        if pipe_id not in self.state[node_id]:
            return None

        return self.state[node_id][pipe_id]

    def set_state(self, node_id, pipe_id, state, data=None):
        # Update session counter.
        self.active_no += 1

        # State data format.
        info = {
            "node_id": node_id,
            "pipe_id": pipe_id,
            "state": state,
            "data": data,
            "timestamp": timestamp()
        }

        # Create session table for node.
        if node_id not in self.state:
            self.state[node_id] = {}

        # Set state for node.
        self.state[node_id][pipe_id] = info

    """
    Handles closing any open STUN handles.

    Removes a specific state dictionary. Decrease session counters.
    May remove session counter when zero.
    """
    async def cleanup_state(self, node_id, pipe_id):
        # Does the state exist?
        state_info = self.get_state_info(node_id, pipe_id)
        if state_info is None:
            return 0

        # Close any open STUN sockets.
        if "data" in state_info:
            data = state_info["data"]
            if "lmaps" in data:
                for sock in data["lmaps"]["stun_socks"]:
                    if sock is not None:
                        await sock.close()

        # Delete dest@session = session.
        del self.state[node_id][pipe_id]

        # If it was the last pipe delete the whole struct.
        if not len(self.state[node_id]):
            del self.state[node_id]

        if self.active_no:
            self.active_no -= 1

        return 1
        
    """
    The TCP hole punching process builds up connection state.
    It's important that old state gets deleted to avoid filling up memory.
    This is a simple coroutine that fires up every 10 mins.
    It cleans up all stale state and then sleeps.
    """
    async def cleanup_by_timeout(self, max_elapsed=5 * 60):
        while not self.stop_running.is_set():
            now = timestamp()
            async def do_cleanup(state_info):
                elapsed = now - state_info["timestamp"]
                if elapsed >= max_elapsed:
                    await self.cleanup_state(
                        state_info["node_id"],
                        state_info["pipe_id"]
                    )

            # Check for timeouts every ten mins.
            try:
                await asyncio.wait_for(
                    self.stop_running.wait(),
                    max_elapsed
                )
            except asyncio.TimeoutError:
                pass

            # Check timeout for all active sessions, for all dests.
            """
            The cleanup isn't done in the loop because changing the
            size of state while iterating over it with keys causes
            an exception. Instead the cleanup tasks are saved and
            then run sequentially.
            """
            tasks = []
            for node_id in self.state.keys():
                for pipe_id in self.state[node_id].keys():
                    state_info = self.get_state_info(node_id, pipe_id)
                    tasks.append(do_cleanup(state_info))

            # Cleanup all state structs.
            for task in tasks:
                await task

        self.tcp_punch_stopped.set()

    # Initiator: Step 1 -- send Initiators predicted mappings to Recipient.
    async def proto_send_initial_mappings(self, dest_addr, dest_nat, dest_node_id, pipe_id, stun_client, process_replies=None, con_list=None, mode=TCP_PUNCH_REMOTE):
        assert(stun_client.interface == self.interface)

        # Log warning if dest_addr is our ext address.
        af = af_from_ip_s(dest_addr)
        ext = self.interface.route(af).ext()
        if dest_addr == ext:
            log("> TCP punch warning: step 1 dest matches our dest.")

        # Session id is simple len of existing sessions.
        map_info = await get_nat_predictions(
            mode,
            stun_client,
            self.interface.nat,
            dest_nat
        )

        """
        The NAT prediction code tries to choose ports in a way
        where both parties trying to connect can use the same
        remote port. The reason for this is if host A knows that
        host B will also try use the same ports -- then it may
        be able to connect to host B even if host B can't get
        back a message to host A with its remote mappings.

        It's not always possible to do this depending on the
        NAT types involved. But it's done when it's possible.
        Just another way I wanted to make this code more robust.
        """

        # Triggered on receiving updated mappings (if any.)
        update_event = asyncio.Event()
        
        # Save session data.
        our_maps = map_info_to_their_maps(map_info)
        ntp_meet = self.get_ntp_meet_time()
        data = {
            # Defines the algorithm used for punching.
            "mode": mode,

            # Event for step 3.
            "update_event": update_event,

            # The NAT predictions for ourself live here.
            "lmaps": map_info,

            # By default assume their maps will be our maps.
            # Overwritten if we receive a reply.
            "rmaps": our_maps,

            # Their NAT struct.
            "their_nat": dest_nat,

            # Their dest.
            "their_dest": dest_addr,

            # Their node id.
            "their_node_id": dest_node_id,

            # Pipe ID used for session.
            "pipe_id": pipe_id,

            # These are all optional:
            ##########################

            # Protocol handler that runs for a punched con.
            "process_replies": process_replies,

            # Used for cleanup / insert to shared state.
            "con_list": con_list,

            # Future time for hole punching to occur.
            "ntp_meet": ntp_meet
        }

        # First state progression -- no need to check existing.
        self.active_no += 1
        self.set_state(
            dest_node_id,
            pipe_id,
            TCP_PUNCH_SEND_INITIAL_MAPPINGS,
            data
        )

        return our_maps, ntp_meet, update_event

    # Recipient: Step 2 -- get Initiators mappings. Generate our own.
    async def proto_recv_initial_mappings(self, recv_addr, recv_nat, recv_node_id, pipe_id, their_maps, stun_client, ntp_meet=0, process_replies=None, con_list=None, mode=TCP_PUNCH_REMOTE):
        assert(stun_client.interface == self.interface)

        # Invalid len.
        if not is_valid_rmaps(their_maps):
            log("> tpc punch recv: invalid rmaps")
            return None
        their_maps = rmaps_strip_duplicates(their_maps)
        if not valid_mappings_len(their_maps):
            log("> tpc punch recv: invalid rmaps len")
            return None

        # Log warning if dest_addr is our ext address.
        af = af_from_ip_s(recv_addr)
        ext = self.interface.route(af).ext()
        if recv_addr == ext:
            log("> TCP punch warning: step 2 recv matches our dest.")

        # Should be no other state progressions.
        existing = self.get_state_info(recv_node_id, pipe_id)
        if existing is not None:
            log("> tpc punch recv: state exists")
            return None

        # Get NAT predictions relative to theirs.
        # If required (and if we can) - change our bind port.
        map_info = await get_nat_predictions(
            mode,
            stun_client,
            self.interface.nat,
            recv_nat,
            their_maps
        )

        # Expect them to use our reply port if set.
        """
        It's possible that the Initiator has already chosen a remote
        port that matches what our reply port will be. In which case
        this code will have no effect. The code intelligently
        selects ports to use based on its partners NAT type.

        Consequently, the Initiator doesn't always need a reply
        from the Recipient. For example: if you lookup a NAT mapping
        via STUN on a 'port restricted NAT' then the NAT will need
        a peer to use the same port as the STUN service for the
        mapping to be used. STUN listens on a common port so this
        may be selected by the Initator in advance.
        """
        if mode != TCP_PUNCH_SELF:
            x = len(map_info["reply"])
            y = len(their_maps)
            for i in range(0, min(x, y)):
                if map_info["reply"][i]:
                    # Overwrite their remote port.
                    their_maps[i][0] = map_info["reply"][i]

        # State data to change.
        data = {
            "mode": mode,
            "lmaps": map_info,
            "rmaps": their_maps,
            "process_replies": process_replies,
            "con_list": con_list,
            "ntp_meet": ntp_meet,
            "their_nat": recv_nat,
            "their_dest": recv_addr,
            "their_node_id": recv_node_id,
            "pipe_id": pipe_id
        }

        # Update state.
        self.active_no += 1
        our_maps = map_info_to_their_maps(map_info)
        self.set_state(
            recv_node_id,
            pipe_id,
            TCP_PUNCH_RECV_INITIAL_MAPPINGS,
            data
        )

        # Sent update won't be important.
        # I just wanted the first two sides to have the same ret.
        sent_update = asyncio.Event()
        return our_maps, ntp_meet, sent_update
        
    """
    Initiator: optional -- may receive Recipients mappings.
    If they do not, then they assume they are using any
    specified reply ports or the same mappings as their own.
    Obviously only possible based on Recipients NAT.
    Such a step is --required-- if attemping to punch self
    as both sides will need to use unique bind ports.
    """
    async def proto_update_recipient_mappings(self, dest_node_id, pipe_id, their_maps, stun_client):
        if stun_client.interface != self.interface:
            raise Exception("Invalid interface.")

        # Invalid len.
        if not is_valid_rmaps(their_maps):
            log("> update map -- invalid rmaps")
            return None
        their_maps = rmaps_strip_duplicates(their_maps)
        if not valid_mappings_len(their_maps):
            log("> update map -- invalid len")
            return None

        # Short-hand references to huge names.
        state_info = self.get_state_info(dest_node_id, pipe_id)
        if state_info is None:
            log("> update map -- state info none")
            return None
        data = state_info["data"]
        lmaps = data["lmaps"]

        # Only possible after initial state update.
        test_no = len(their_maps)
        use_range = nats_intersect_range(self.interface.nat, data["their_nat"], test_no)
        bad_delta = [INDEPENDENT_DELTA, DEPENDENT_DELTA, RANDOM_DELTA]
        if state_info["state"] == TCP_PUNCH_SEND_INITIAL_MAPPINGS:
            # Update our local ports if needed.
            for i in range(0, test_no):
                _, reply_port, _ = their_maps[i]
                if reply_port:
                    # We can satisfy their requirements.
                    if self.interface.nat["delta"]["type"] not in bad_delta:
                        # local, remote, reply, sock.
                        m, _ = await get_single_mapping(
                            data["mode"],
                            their_maps[i],
                            lmaps["last_mapped"],
                            use_range,
                            self.interface.nat,
                            stun_client
                        )

                        # Update our local port.
                        if data["mode"] != TCP_PUNCH_SELF:
                            new_local, _, _, _ = m
                            lmaps["local"][i] = new_local
                            lmaps["remote"][i] = reply_port

                    # Else = they can't connect.
            
            # Trucate our maps if needed.
            data["rmaps"] = their_maps
            lmaps["local"] = lmaps["local"][:test_no]
            lmaps["remote"] = lmaps["remote"][:test_no]
            lmaps["reply"] = lmaps["reply"][:test_no]
            
            # Indicate our recipient mappings were updated.
            self.set_state(
                dest_node_id,
                pipe_id,
                TCP_PUNCH_UPDATE_RECIPIENT_MAPPINGS,
                data
            )

            data["update_event"].set()
            return self.get_state_info(dest_node_id, pipe_id)
        else:
            log("> update map -- invalid state")
            data["update_event"].set()

    # Both sides: step 3.
    """
    I use 'SO_REUSEPORT' to open another connect
    socket and keep the other STUN sockets open.
    """
    @staticmethod
    async def do_punching(side, interface, our_wan, dest_addr, af, local, remote, rmaps, current_ntp, ntp_meet, mode, sock_queue):
        """
        Punching is done in its own process.
        The process returns an open socket and Python
        warns that the socket wasn't closed properly.
        This is the intention and not a bug!
        This code disables that warning.
        """
        warnings.filterwarnings('ignore', message="unclosed", category=ResourceWarning)

        # Init.
        log(f"> TCP punch interface rp pool")
        log_interface_rp(interface)
        is_connected = [False]
        socks = []

        # If NTP meet is defined then wait for it to occur.
        if ntp_meet:
            # NTP meet time is too large -- set to max.
            """
            max_meet_time = current_ntp + NTP_MEET_STEP
            if max_meet_time < ntp_meet:
                ntp_meet = max_meet_time
            """

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

        """
        We can keep trying until success without the mappings
        changing. However, unpredictable nats that use
        delta N will be timing sensitive. If timing info
        is available the protocol should try use that.
        """
        async def delay_con(start_time, ms_delay, local_port, remote_port, dest, sock_timeout, is_connected, loop):
            # Used for making new cons.
            conf = copy.deepcopy(PUNCH_CONF)
            conf["con_timeout"] = sock_timeout 

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
            route = await interface.route(af).bind(local_port)

            # Open connection -- return only sock.
            #sock = await pipe_open(route, TCP, dest, conf=PUNCH_CONF) 
            sock = await socket_factory(route, dest, conf=PUNCH_CONF)
            #sock_queue.put_nowait(sock)
            #sock.settimeout(0.1)
            try:
                await loop.sock_connect(
                    sock,
                    dest.tup
                )
            except:
                return None

            # Failure.
            # We strip None responses out.
            if sock is None:
                return None
            else:
                is_connected[0] = True

            """
            At some point I expect errors to be made if a
            local IP + local port is reused for the same
            dest IP + dest port and it successfully gets
            connected. So successive calls might fail.
            """
            return [remote_port, sock]


        """
        Smarter code that is less spammy used for remote
        punching. Won't overwhelm the event loop like the
        above code will. Takes advantage of the massive timeouts
        in the Internet as packets travel across routers.
        Optimized and tested for remote connections.
        """
        async def remote_mode(dest_addr, af, interface, local, remote, rmaps, is_connected):
            #print("mode = remote")
            #print(f"bound on {local}")

            # Con occuring every 
            # second for 3 seconds for
            # all tests at once.
            secs = 6
            ms_spacing = 5
            cons = []
            tasks = []
            start_time = timestamp(1)
            steps = int((secs * 1000) / ms_spacing)
            route = interface.route(af)
            log(f"TCP PUNCH REMOTE local = {local}")
            for i in range(0, len(local)):
                dest = await Address(dest_addr, rmaps[i][0]).res(route)
                #print(f"connect to {dest.tup}")
                for sleep_time in range(0, steps):
                    tasks.append(
                        delay_con(
                            # Record start time for logging.
                            start_time,

                            # Wait until ms to do punching.
                            # Punches are split up over time
                            # to increase chances of success.
                            sleep_time * ms_spacing,

                            # Local ports to bind to.
                            local[i],

                            # Used to choose a single con.
                            remote[i],

                            # Destination addr to connect to.
                            dest,

                            # This prevents cons
                            # from being scheduled later
                            # on and exceeding total secs
                            2,
                            is_connected,
                            asyncio.get_event_loop()
                        )
                    )
            
            # Start running tasks.
            all_tasks = asyncio.gather(*tasks)
            outs = await all_tasks
            outs = strip_none(outs)
            return outs

        log("In punch. mode = ")
        log(mode)

        # Use local punching algorithm.
        
        if mode in [TCP_PUNCH_SELF, TCP_PUNCH_LAN]:
            # Updated mapping error occured.
            # Cannot bind to same port as other side on same host.
            if mode == TCP_PUNCH_SELF and remote[0] == rmaps[0][0]:
                log("> Punch updated mapping error for punch self.")
                return None

            # Punch local -- use same algorithm as remote.
            outs = await remote_mode(
                dest_addr=dest_addr,
                af=af,
                interface=interface,
                local=local,
                remote=remote,

                # rmap = [ remote, reply, local ]
                # connect to their local port.
                rmaps=[[rmap[2]] for rmap in rmaps],
                is_connected=is_connected
            )

        # Use remote punching algorithm.
        if mode == TCP_PUNCH_REMOTE:
            outs = await remote_mode(
                dest_addr=dest_addr,
                af=af,
                interface=interface,
                local=local,
                remote=remote,
                rmaps=rmaps,
                is_connected=is_connected
            )

        # Make both sides choose the same socket.
        #print(outs)
        try:
            our_ip_num = ip_str_to_int(our_wan)
            chosen_sock = None
            h_val = 0
            for remote_port, sock in outs:
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

        # Close all other sockets that aren't needed.
        for _, sock in outs:
            if sock != chosen_sock:
                sock.close()
                pass
        
        # Return sock result.
        if chosen_sock is not None:
            return chosen_sock
        else:
            log("> tcp punch chosen sock is none")
            return None

    def get_punch_args(self, node_id, pipe_id):
        # Get associated state.
        state_info = self.get_state_info(node_id, pipe_id)
        if state_info is None:
            raise Exception("cant find state.")

        dest_addr = state_info["data"]["their_dest"]
        af = af_from_ip_s(dest_addr)
        lmaps = state_info["data"]["lmaps"]
        rmaps = state_info["data"]["rmaps"]
        interface = self.interface
        current_ntp = 0
        if self.sys_clock is not None:
            current_ntp = self.sys_clock.time()
    
        return [
            interface,
            interface.route(af).ext(),
            dest_addr,
            af,
            lmaps["local"],
            lmaps["remote"],
            rmaps,
            current_ntp,
            state_info["data"]["ntp_meet"]
        ]

    """
    This function schedules TCP hole punching to run in
        - a new process
        - a new event loop in said process
        - and handles shared memory of resources
    """
    async def proto_do_punching(self, side, node_id, pipe_id, msg_cb=None):
        # Get associated state.
        state_info = self.get_state_info(node_id, pipe_id)
        if state_info is None:
            log("Cant find state info in proto do punching.")
            return None

        # These arguments are all able to be 'pickled.'
        # This requirement is annoying as hell.
        dest_addr = state_info["data"]["their_dest"]
        queue = self.queue_manager.Queue()
        af = af_from_ip_s(dest_addr)
        route = self.interface.route(af)
        addr = await Address(dest_addr, 0).res(route)
        args = self.get_punch_args(node_id, pipe_id)
        args.append(state_info["data"]["mode"])
        args.append(queue)
        args.append(self.sock_queue)
        args.append(side)
        
        # The executor pool is used to start processes.
        loop = asyncio.get_event_loop()
        assert(self.executors is not None)
        loop.run_in_executor(
            self.executors, proc_do_punching, args
        )

        # Wait for queue result with timeout.
        for _ in range(0, 30):
            if not queue.empty():
                break

            await asyncio.sleep(1)

        # Process return result.
        sock = queue.get(timeout=2)
        pipe = None
        if sock is not None: 
            log(f"> TCP hole made {sock}.")
            route = await self.interface.route(af).bind(
                sock.getsockname()[1]
            )

            pipe = await pipe_open(
                route=route,
                proto=TCP,
                dest=await Address(
                    *sock.getpeername()
                ).res(route),
                sock=sock,
                msg_cb=msg_cb
            )

        # Cleanup state.
        if self.do_state_cleanup:
            await self.cleanup_state(node_id, pipe_id)

        return pipe
    
async def test_tcp_punch(): # pragma: no cover
    # Use IPv4 for protocol.
    """
    import resource
    resource.setrlimit(resource.RLIMIT_NOFILE, (100000, 100000))
    """
    sabotage = False
    af = socket.AF_INET
    executors = ProcessPoolExecutor()
    m = multiprocessing.Manager()
    loop = asyncio.get_event_loop()

    """
    K, reusing works.
    bind_tup = ("192.168.21.141", 58133)
    sock_a = socket.socket(AF_INET, SOCK_STREAM)
    sock_a.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_a.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock_a.bind(bind_tup)

    sock_b = socket.socket(AF_INET, SOCK_STREAM)
    sock_b.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_b.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock_b.bind(bind_tup)

    return
    """

    internode_nat = nat_info(FULL_CONE, delta_info(PRESERV_DELTA, 0))
    starlink_nat = nat_info(RESTRICT_PORT_NAT, delta_info(RANDOM_DELTA, 0), [34000, MAX_PORT])

    # nat type = 5 (restrict nat) - preserving delta.
    # Sends to invalid dest port -- where the hell
    # is this dest port coming from??
    #interfaces = await Interfaces(["enp3s0", "wlp2s0"]).load()
    #internode_out = interfaces.by_name("enp3s0")
    internode_out = await Interface("enp3s0").start()
    internode_out.set_nat(internode_nat)


    #sys_clock = await SysClock().start()
    sys_clock = None # disable for testing

    #print(internode_out.wan_ips)
    #return
    internode_stun_client = STUNClient(internode_out)
    internode_dest = internode_out.route(af).ext()
    
    """
    if sabotage:
        internode_dest = await Address(
            "123.123.233.3",
            0
        ).res()
    """
    print(internode_dest)


    initiator = internode_tcp_punch = TCPPunch(
        internode_out,
        None,
        sys_clock,
        executors,
        m
    )

    # NAT type = restrict port nat, random delta.
    #starlink_out = interfaces.by_name("wlp2s0")
    #print("starlink out wan ips = %s " % (str(starlink_out.wan_ips)))
    starlink_out = await Interface("wlp2s0").start()
    starlink_out.set_nat(starlink_nat)


    starlink_dest = starlink_out.route(af).ext()
    """
    if sabotage:
        starlink_dest = internode_dest
    """

    print(starlink_dest)

    starlink_stun_client = STUNClient(starlink_out)
    #delta = await mapping_test(internode_stun_client)
    #print(delta)

    recipient = starlink_tcp_punch = TCPPunch(
        starlink_out,
        None,
        sys_clock,
        executors,
        m
    )

    """
    local_port = await recipient.brute_force_mapping(40000)
    print(local_port)
    if local_port is None:
        return
    ret = await starlink_stun_client.get_mapping(SOCK_STREAM, source_port=local_port)
    print(ret)

    return
    """

    # Step 1 -- set initial mappings for initiator.
    i_session, i_their_maps, i_ntp_meet = await initiator.proto_send_initial_mappings(
        starlink_dest,
        starlink_nat,
        internode_stun_client
    )

    
    print("I punch details:")
    print(i_session)
    print(i_their_maps)
    print(i_ntp_meet)
    print(initiator.state)
    print()

    # Step 2 -- exchange initiator mappings with recipient.
    # Details would be exchanged over another data channel.
    # In our protocol the SIP client is designed for that.
    r_session, r_their_maps, r_ntp_meet = await recipient.proto_recv_initial_mappings(
        internode_dest,
        internode_nat,
        i_session,
        i_their_maps,
        starlink_stun_client,
        i_ntp_meet
    )

    print("R punch details:")
    print(recipient.state)
    print()

    # Optional step -- update mappings of recipient.
    i_state_info = await initiator.proto_update_recipient_mappings(starlink_dest, i_session, r_their_maps, internode_stun_client)

    print("I state info after update their maps")
    print(initiator.state)
    print()

    print("internode dest = %s" % (internode_dest))
    print("starlink dest = %s" % (starlink_dest))

    results = await asyncio.gather(
        initiator.proto_do_punching(starlink_dest, i_session),
        recipient.proto_do_punching(internode_dest, r_session)
    )

    results = strip_none(results)
    print(results)

    """
    if len(results) >= 2:
        con1, con2 = results
        con1 = await con1.send(b"this is a test")
        data = await con2.recv_n(1024)
        print(data)

    print(results)
    """

    print("Started, now sleeping.")
    while 1:
        await asyncio.sleep(1)

    """
    await asyncio.gather(
        initiator.proto_do_punching(starlink_dest, i_session),
        #recipient.proto_do_punching(internode_dest, r_session)
    )
    """

    return

    # Optional step (but sometimes necessary depending on receiver nat type) -- receiver exchanges
    # their mapping info back to initiator.

    """
    observation: since the stun servers all listen on the
    same port then clients that are port restricted are all
    going to request the same reply ports which is kind of
    not ideal to have 5 identical tests on its partner running
    
    options:
        - less tests? - not ideal
        - more variety in reply ports
            - can use the change port at least
        - research hosts with non-standard bind ports?

    """


    return

    """
    concurrent tcp punches:

    protocol = 

    """



    return

    #delta = await delta_n_test(stun_client)
    #print("Delta = %d" % (delta))



    """
    class TCPPunch():
    def __init__(self, interfaces, stun_client, nat_type=RestricPortNAT, delta=RANDOM_DELTA):
    """

if __name__ == "__main__": # pragma: no cover
    async_test(test_tcp_punch)