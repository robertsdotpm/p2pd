"""
Old module problems:

- God object - lets use isolated classes that encapsulate state for one set of peers.
    - factory management with member objects in same object
    - no separation of concerns
- 1300 lines - move utils to own file, do reset of cleanup later
- multiple data formats for the mappings?
    - mappings data type and logic scattered throughout
- duplicate code for init mappings and recv init mappings
- do_punching
    - static method that would be better in a process module
    - remote mode and local mode almost exactly the same
- lengthy test code that is outdated
"""

"""
proto uses 'our maps' map info to their maps
'their maps'
- list of lists which are [remote reply local]
- proto also uses ntp meet time

map_info is from 'get_nat_predictions'
    - so wrong format

This code needs to be moved to the get_nat_predictions func.
    - pass it a side parameter
    # initiator
    if mode == TCP_PUNCH_SELF:
        rmaps = copy.deepcopy(map_info)
        patch_map_info_for_self_punch(rmaps)
        rmaps = map_info_to_their_maps(rmaps)

    # recipient
    if mode != TCP_PUNCH_SELF:
        x = len(map_info["reply"])
        y = len(their_maps)
        for i in range(0, min(x, y)):
            if map_info["reply"][i]:
                # Overwrite their remote port.
                their_maps[i][0] = map_info["reply"][i]

    # recipient
    if mode == TCP_PUNCH_SELF:
    our_maps = copy.deepcopy(map_info)
    patch_map_info_for_self_punch(our_maps)
    our_maps = map_info_to_their_maps(map_info)

- in that light:
    - get nat predictions probably needs to be broken into funcs
    - this function is ungodly

       # Updated mapping error occured.
        # Cannot bind to same port as other side on same host.
        if mode == TCP_PUNCH_SELF:

            if send_mappings[0]
        and remote[0] == rmaps[0][0]:
            log("> Punch updated mapping error for punch self.")
            return None

add a check func for that kind of thing for
    send_map.. vs recv_map to find contradictions
"""

import asyncio
from .nat_rewrite import *
from .tcp_punch_utils import *
from .clock_skew import *

class TCPPunchFactory:
    def __init__(self):
        # by pipe_id, node_id
        self.clients = {}

class TCPPuncher():
    def __init__(self, af, src_info, dest_info, stun, sys_clock, same_machine=False):
        # Save input params.
        self.af = af
        self.src_info = src_info
        self.dest_info = dest_info
        self.stun = stun
        self.sys_clock = sys_clock
        self.same_machine = same_machine

        # Short hands.
        self.set_interface()
        self.set_punch_mode()
        self.side = self.state = None
        self.pipe_id = self.node = None
        self.start_time = Dec(0)
        self.recv_mappings = []
        self.send_mappings = []
        self.preloaded_mappings = []

    def set_parent(self, pipe_id, node):
        self.pipe_id = pipe_id
        self.node = node

    def set_interface(self):
        self.if_index = self.src_info["if_index"]
        if self.stun is not None:
            self.interface = self.stun.interface
        else:
            self.interface = None

    def set_punch_mode(self):
        self.punch_mode = get_punch_mode(
            self.af,
            str(self.dest_info["ip"]),
            self.same_machine
        )

    def setup_multiproc(self, pp_executor, mp_manager):
        # Process pools are disabled.
        if pp_executor is None:
            self.pp_executor = None
            self.mp_manager = None
            return
            
        assert(mp_manager)
        self.pp_executor = pp_executor
        self.mp_manager = mp_manager

    def get_ntp_meet_time(self):
        return self.sys_clock.time() + Dec(NTP_MEET_STEP)
    
    async def proto(self, recv_mappings=None, start_time=None):
        # Change protocol state transition.
        self.state, self.side = tcp_puncher_states(
            recv_mappings,
            self.state,
        )

        # Covers exchanging and receiving mappings.
        # These steps are required for success.
        fetch_states  = [INITIATED_PREDICTIONS]
        fetch_states += [RECEIVED_PREDICTIONS]
        if self.state in fetch_states:
            self.send_mappings, self.preloaded_mappings = \
                await mock_nat_prediction(
                    self.punch_mode,
                    self.src_info["nat"],
                    self.dest_info["nat"],
                    self.stun,
                    recv_mappings=recv_mappings,
                )

            # Ii receive mapping isn't set use templates.
            self.recv_mappings = \
                recv_mappings or self.send_mappings
            
            # Set meeting start time.
            arrange_time = self.get_ntp_meet_time()
            self.start_time = \
                start_time or arrange_time

            # Only things needed for protocol.
            return self.send_mappings, self.start_time
                
        # Update the  mapping to match needed reply ports.
        # Optional step but improves success chance.
        if self.state == UPDATED_PREDICTIONS:
            print("in updated mappings")
            update_nat_predictions(
                self.punch_mode,
                self.src_info["nat"],
                self.dest_info["nat"],
                self.preloaded_mappings,
                self.send_mappings,
                recv_mappings
            )

            return 1
        
    async def setup_punching_process(self):
        # The executor pool is used to start processes.
        loop = asyncio.get_event_loop()

        if self.mp_manager is not None:
            queue = self.mp_manager.Queue()
        else:
            queue = None

        # Multiprocessing pool is enabled.
        if self.pp_executor is not None:
            print("executors enabled")
            # test
            args = (
                queue,
                self.to_dict(),
            )
            
            # Schedule TCP punching in process pool executor.
            loop.run_in_executor(
                self.pp_executor,
                proc_do_punching,
                args
            )

            # Wait for queue result with timeout.
            for _ in range(0, 30):
                if not queue.empty():
                    break

                await asyncio.sleep(1)

            # Executor pushes back socket to queue.
            try:
                sock = queue.get(timeout=2)
            except Exception:
                log_exception()
                sock = None
        
        # Wrap returned socket in a pipe.
        pipe = None
        try:
            if sock is not None: 
                log(f"> TCP hole made {sock}.")
                route = await self.interface.route(self.af).bind(
                    sock.getsockname()[1]
                )

                pipe = await pipe_open(
                    route=route,
                    proto=TCP,
                    dest=Address(
                        *sock.getpeername(),
                    ),
                    sock=sock,
                    msg_cb=self.node.msg_cb
                )

                self.node.pipe_ready(self.pipe_id, pipe)
                print(pipe_id)
                print("after pipe ready")
        except:
            log_exception()

        return pipe

    def to_dict(self):
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
    
    @staticmethod
    def from_dict(d):
        interface = Interface.from_dict(d["interface"])
        recv_mappings = mappings_dicts_to_objs(d["recv_mappings"])
        send_mappings = mappings_dicts_to_objs(d["send_mappings"])
        sys_clock = SysClock.from_dict(d["sys_clock"])
        puncher = TCPPuncher(
            af=d["af"],
            src_info=d["src_info"],
            dest_info=d["dest_info"],
            stun=None,
            sys_clock=sys_clock,
            same_machine=d["same_machine"]
        )
        puncher.state = d["state"]
        puncher.side = d["side"]
        puncher.punch_mode = d["punch_mode"]
        puncher.recv_mappings = recv_mappings
        puncher.send_mappings = send_mappings
        puncher.start_time = Dec(d["start_time"])
        puncher.interface = interface
        return puncher

# Started in a new process.
def proc_do_punching(args):
    """
    On Windows it seems like using the default 'proactor event loop'
    prevents the TCP hole punching code from working. It seems that
    manually setting the event loop to use SelectorEventLoop
    fixes the issue. However, this may mean breaking some of
    my command execution code on Windows -- test this.
    """
    asyncio.set_event_loop_policy(SelectorEventPolicy())

    # Build a puncher from a dictionary.
    q = args[0]
    d = args[1]
    puncher = TCPPuncher.from_dict(d)

    print(puncher.send_mappings)
    print(puncher.recv_mappings)
    print(puncher.punch_mode)
    print(d)

    # Execute the punching in a new event loop.
    loop = asyncio.get_event_loop()
    f = asyncio.ensure_future(
        async_wrap_errors(
            do_punching(
                puncher.af,
                puncher.dest_info["ip"],
                puncher.send_mappings,
                puncher.recv_mappings,
                puncher.sys_clock.time(),
                puncher.start_time,
                puncher.punch_mode,
                puncher.interface
            )
        ),
        loop=loop
    )

    # The moment the function is done save its result to the queue.
    # The queue is sharable and works with basic types.
    f.add_done_callback(lambda t: q.put(t.result()))
    loop.run_until_complete(f)

##################################################
# Workspace
if __name__ == "__main__":
    class MockInterface:
        def __init__(self):
            self.nat = None

    class NodeMock:
        def __init__(self):
            self.ifs = [MockInterface()]

    alice_node = NodeMock()
    bob_node = NodeMock()

    ds_info = {
        "nat": None,
        "if_index": 0
    }

    src_info = ds_info
    dest_info = ds_info

    stun_client = "placeholder"

    pipe_id = "my pipe"
    alice_node_id = "alice node id"
    bob_node_id = "bob node id"
    alice_dest = {}
    bob_dest = {}

    alice_punch = TCPPuncher(src_info, dest_info, alice_node)
    bob_punch = TCPPuncher(src_info, dest_info, bob_node)

    print(alice_punch)
    print(bob_punch)

    n_map = NATMapping([23000, -1, 23000])
    recv_mappings = [n_map]
    alice_punch.proto_predict_mappings(stun_client)
    alice_punch.proto_predict_mappings(stun_client, recv_mappings)
    bob_punch.proto_predict_mappings(stun_client, recv_mappings)
