import pickle
import asyncio
from aionetiface import *
from ....protocol.traversal.proto_msg import PunchMsg, DoneMsg
from ...libs.punch.punch_defs import *
from ...libs.punch.utility.punch_utils import *
from ...libs.punch.utility.boundary_lib import FAST_PUNCH_PARAMS
from ...libs.punch.punch_client import *
from ...libs.punch.port_allocators.nat_predict_alloc import *
from ...libs.punch.punch_process import *
from ...libs.nat_predict import *
from ...traversal_plugin import TraversalPlugin

def find_unpicklable(obj, path="obj", seen=None):
    if seen is None:
        seen = set()

    # avoid infinite recursion
    obj_id = id(obj)
    if obj_id in seen:
        return None
    seen.add(obj_id)

    # try direct pickle
    try:
        pickle.dumps(obj)
        return None  # picklable
    except Exception as e:
        fail = (path, obj, e)

    # explore container contents
    if isinstance(obj, dict):
        for k, v in obj.items():
            r = find_unpicklable(v, f"{path}[{k!r}]", seen)
            if r:
                return r

    if isinstance(obj, (list, tuple, set, frozenset)):
        for i, v in enumerate(obj):
            r = find_unpicklable(v, f"{path}[{i}]", seen)
            if r:
                return r

    # inspect normal objects
    if hasattr(obj, "__dict__"):
        for k, v in vars(obj).items():
            r = find_unpicklable(v, f"{path}.{k}", seen)
            if r:
                return r

    return fail

class PunchPlugin(TraversalPlugin):
    async def run(self, reply=None):
        punch_time = 0.0
        puncher = self.punch_clients.get(self.pipe_id)
        if puncher:
            # Case 1: Continue existing NAT traversal exchange
            punch_time = puncher.punch_time
        else:
            # Case 2: Start a new NAT traversal exchange
            puncher, stuns = await self.setup_puncher_client(reply)
            if puncher is None:
                log("PunchPlugin: no STUN clients available; aborting punch.")
                return # Abort if no STUN configuration is available

            # Re-check after the await: a concurrent run() for the same
            # pipe_id may have raced through setup_puncher_client and already
            # stored a puncher.  Reusing that one avoids a second punching
            # process and a state mismatch where punch_proc holds a reference
            # to a different PunchClient than punch_clients.
            existing = self.punch_clients.get(self.pipe_id)
            if existing is not None:
                puncher = existing
            else:
                # Setup predictions and start process waiter.
                puncher = await self.configure_puncher_process(puncher, stuns)
            punch_time = puncher.punch_time

        # --- Advance the State Machine ---
        # Calculate the next step of port predictions.
        outgoing_msg = await self.advance_punching_protocol(
            puncher, 
            reply, 
            punch_time
        )

        if outgoing_msg is None:
            return

        # Send the control message.
        await self.signal_msg_sender(outgoing_msg)

    # ... (other methods, including delayed_start_punching_proc) ...
    async def delayed_start_punching_proc(self, nic, puncher):
        # Wait for the peer to receive our message and set up its own process.
        # The delay is kept short when using FAST_PUNCH_PARAMS because the
        # rendezvous window is small and synchronised via sleep_until().
        coordinator_delay = puncher.params.get("coordinator_delay", 2.0)
        try:
            await asyncio.sleep(coordinator_delay)

            """
            bad = find_unpicklable(puncher)
            if bad:
                path, value, error = bad
                print("Unpicklable at:", path)
                print("Type:", type(value))
                print("Error:", error)
            """

            pipe = await start_punching_process(
                nic,
                puncher,
                self.stop_reader,
                self.proc_pool,
            )

            # Guard against a second concurrent call resolving the same future,
            # which would raise asyncio.InvalidStateError.
            if not self.result.done():
                #self.result.add_msg_cb(self.node.msg_cb)
                self.result.set_result(pipe)
        finally:
            # Always remove shared state so subsequent attempts start clean.
            # This runs on normal completion, cancellation, and exceptions.
            self.punch_proc.pop(self.pipe_id, None)
            self.punch_clients.pop(self.pipe_id, None)

    async def close(self):
        """Cancel any in-flight punch task and remove this plugin's shared state.

        Safe to call multiple times: pop() is a no-op when the key is absent
        and task/future guards check done() before acting.
        """
        task = self.punch_proc.pop(self.pipe_id, None)
        self.punch_clients.pop(self.pipe_id, None)
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        # Cancel the result future if nobody resolved it (e.g. outer timeout).
        if not self.result.done():
            self.result.cancel()

    async def setup_puncher_client(self, reply):
        """
        Determines the source/destination addresses and the decider IP, 
        creates a new PunchClient, and sets the coordinated time references.
        """
        print("in setup punching client.")
        if_index = self.src_info["if_index"]
        stuns = self.stun_clients[self.af][if_index]

        # Skip if no STUN clients loaded.
        if not len(stuns):
            print("no stun clients in setup puncher client.")
            return None, None
        
        # 1. Determine IP Addresses via Routing
        route = await self.nic.route(self.af).bind()
        dest_ip = self.dest_info["ip"]
        if "fe80" == dest_ip[:4]:
            # Use link-local source for link-local destination
            src_ip = str(route.link_locals[0])
        else:
            # Use the interface's local IP
            src_ip = route.nic()

        # 2. Determine the 'Decider' IP for Master/Slave Role Selection
        if self.route_type == NIC_BIND:
            decider_ip = src_ip
        else:
            decider_ip = route.ext()

        print("punch dest ip = ", dest_ip)

        # 3. Create and Configure PunchClient
        # FAST_PUNCH_PARAMS is used for network-protocol punching: the punch_time
        # is communicated between peers via PunchMsg so we do not need the large
        # WINDOW / MAX_CLOCK_ERROR values used by the CLI standalone mode.  The
        # tight window (6 s) and short coordinator_delay (0.5 s) cut total punch
        # latency roughly in half compared to the conservative CLI defaults.
        print("nic id = ", self.nic.id)
        print("src ip = ", src_ip)
        print("decider ip = ", decider_ip)
        puncher = PunchClient(
            dest_ip,
            src_ip,
            decider_ip,
            self.nic.id,
            same_machine=self.same_machine,
            params=FAST_PUNCH_PARAMS,
        )

        # 4. Set Coordinated Time References
        timestamp = self.sys_clock.time()
        puncher.set_timestamp(timestamp)
        print("using time stamp = ", timestamp)

        """
        if reply:
            # Use peer's synchronized NTP time
            punch_time = reply.payload.ntp
        else:
        """

        # Calculate a future timestamp to use as the punch time.
        # Use the timing constants from the puncher's params so that the
        # rendezvous window matches the params preset (e.g. FAST_PUNCH_PARAMS).
        p = puncher.params
        _, punch_time = compute_rendezvous(
            timestamp,
            window=p["window"],
            min_run_window=p["min_run_window"],
            max_error=p["max_clock_error"],
        )

        # Set punch time.
        puncher.set_punch_time(punch_time)

        # Deterministic predictions based on boundary math.
        # PunchClient.add_port_allocator forwards self.params to the allocator
        # so it uses the same window / error constants for bucket derivation.
        puncher.add_port_allocator(boundary_port_alloc)
            
        # Return the new puncher and the STUN clients
        return puncher, stuns

    async def configure_puncher_process(self, puncher, stuns):
        """
        Initializes the NAT Prediction Allocator, saves the PunchClient, 
        and schedules the delayed asynchronous punching process.
        """
        # 5. Save Puncher Reference
        self.punch_clients[self.pipe_id] = puncher

        # 6. Initialize NAT Prediction Allocator
        # Note: this just wraps nat_predict.py.
        # There's an aweful lot of bloat just to use code thats already written.
        self.nat_alloc = NATPredictAlloc(stuns)
        self.nat_alloc.set_nat_info(
            self.src_info["nat"], self.dest_info["nat"]
        )
        self.nat_alloc.set_punch_mode(
            self.same_machine, self.dest_info["ip"]
        )
        
        # 7. Schedule the Punching Process (with delay)
        if self.pipe_id not in self.punch_proc:
            self.punch_proc[self.pipe_id] = asyncio.create_task(
                async_wrap_errors(
                    self.delayed_start_punching_proc(self.nic, puncher)
                )
            )
            
        return puncher

    async def advance_punching_protocol(self, puncher, reply, punch_time):
        # 1. Process Received Mappings
        recv_mappings = None
        if reply is not None:
            # Convert raw mappings received from peer into internal objects
            recv_mappings = [NATMapping(m) for m in reply.payload.mappings]
            assert(recv_mappings)

        # 2. Calculate Next Port Allocations (Core NAT Prediction Logic)
        print("recv mappings = ", recv_mappings)
        port_alloc, is_end = await self.nat_alloc.port_alloc(recv_mappings)
        puncher.port_allocs += port_alloc
        #print(puncher.port_allocs)
        
        # 3. Protocol Termination Check
        if is_end == 1:
            # Protocol done.
            return None

        # 4. Prepare Outgoing Control Message
        # Gather mappings generated by this node to send to the peer
        mappings = [m.toJSON() for m in self.nat_alloc.send_mappings]
        msg = PunchMsg({
            "payload": {
                "punch_mode": self.nat_alloc.punch_mode,
                "mappings": mappings,
                "ntp": punch_time,
            },
        })

        msg.meta.plugin_name = "punch"
        return msg

class PunchPluginFactory():
    def __init__(self, stun_clients, punch_clients, sys_clock=None, proc_pool=None):
        self.stun_clients = stun_clients # af if index
        self.sys_clock = sys_clock or SysClock(None, 0.1)
        self.proc_pool = proc_pool
        self.punch_clients = punch_clients
        self.punch_proc = {} # pipe_id: delayed start punching proc task
        self.active_punchers = 0
        return 

    def build_plugin(self):
        plugin = PunchPlugin()
        plugin.stun_clients = self.stun_clients # af if index
        plugin.sys_clock = self.sys_clock
        plugin.proc_pool = self.proc_pool
        plugin.punch_clients = self.punch_clients
        plugin.punch_proc = self.punch_proc

        #plugin.active_punchers = self.active_punchers
        return plugin
        
# TODO
async def tcp_punch_cleanup(tunnel, ):
    tunnel.node.active_punchers = max(
        0,
        tunnel.node.active_punchers - 1
    )

if __name__ == "__main__":
    async def build_punch_proto(af):
        nic = await Interface()
        stun_clients = await get_n_stun_clients(
            af=af,
            n=1,
            interface=nic,
            proto=TCP,
            conf=PUNCH_CONF
        )

        stun_client_table = {
            af: {
                0: stun_clients # 0 = first nic.
            }
        }

        sys_clock = SysClock(nic, 0.1)
        _, proc_pool = await get_pp_executors()
        punch_proto = PunchPluginFactory(
            stun_client_table,
            {}, 
            proc_pool=proc_pool
        ).build_plugin()
        


        punch_proto.nic = nic
        return punch_proto

    async def workspace():
        af = IP4
        punch_proto = await build_punch_proto(af)
        src_info = dest_info = {
            "if_index": 0,
            "ip": "127.0.0.1",
            "nat": nat_info(RESTRICT_PORT_NAT, delta_info(EQUAL_DELTA, 0))
        }

        send_msg = await punch_proto.protocol(
            src_info=src_info,
            dest_info=dest_info,
            nic=punch_proto.nic,
            same_machine=True,
        )

        """
        Pretend out send msg is actually a reply
        from another machine giving us their updated mappings.
        It's our own mappings but this helps test code paths.
        """
        out = await punch_proto.protocol(
            src_info=src_info,
            dest_info=dest_info,
            nic=punch_proto.nic,
            same_machine=True,
            reply=send_msg
        )

        print(send_msg.to_dict())
        print(out)


    async_run(workspace())

