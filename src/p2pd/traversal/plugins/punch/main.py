import pickle
import inspect
import asyncio
from ....utility.utils import *
from ....net.net_utils import *
from ....nic.nat.nat_predict import *
from ...signaling.signal_msgs import PunchMsg, DoneMsg
from .punch_defs import *
from .utility.punch_utils import *
from .punch_client import *
from .port_allocators.nat_predict_alloc import *
from .punch_process import *
from ..traversal_plugin import TraversalPlugin



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
    async def delayed_start_punching_proc(self, nic, puncher):
        # Give time for updated mappings.
        await asyncio.sleep(3)
        print("delay start punching proc.")

        """
        bad = find_unpicklable(puncher)
        if bad:
            path, value, error = bad
            print("Unpicklable at:", path)
            print("Type:", type(value))
            print("Error:", error)
        """


        pipe = await start_punching_process(nic, puncher, self.proc_pool)
        self.pipes[self.pipe_id].set_result(pipe)


    async def run(self, reply=None):
        # Load TCP punch client for this pipe ID.
        if self.pipe_id in self.punch_clients:
            puncher = self.punch_clients[self.pipe_id]

            """
            disable this for now
            assert(self.src_info == puncher.src_info)
            if self.dest_info != puncher.dest_info:
                
                If an address fetch gets an old address a node replies
                with its current address info in a reply which
                is passed back to this function.
                
                log(fstr("<punch> Updating dest info {0}", (self.dest_info,)))
                puncher.dest_info = self.dest_info
            """
        else:
            # Create a new puncher for this pipe ID.
            if_index = self.src_info["if_index"]
            stuns = self.stun_clients[self.af][if_index]

            # Skip if no STUN clients loaded.
            if not len(stuns):
                return None
            
            # Figure out addressing for sockets.
            # Dest IP runs select dest IPR to contextually determine best IP.
            route = await self.nic.route(self.af).bind()
            dest_ip = self.dest_info["ip"]
            if "fe80" == dest_ip:
                src_ip = str(route.link_locals[0])
            else:
                src_ip = route.nic()

            """
            This portion is used in the algorithm to determine the
            "master" or the "slave" for deciding on what sockets
            to use after openning many possible holes.
            """
            if self.route_type == NIC_BIND:
                decider_ip = route.nic()
            else:
                decider_ip = route.ext()

            print("punch dest ip = ", dest_ip)

            # Create a new puncher for this pipe ID.
            puncher = PunchClient(dest_ip, src_ip, decider_ip)

            # Set current unix time using NTP as a reference.
            timestamp = self.sys_clock.time()
            puncher.set_timestamp(timestamp)

            # Set future punching time.
            if reply:
                puncher.set_punch_time(reply.payload.ntp)
            else:
                puncher.set_punch_time(timestamp + 10)

            # Save puncher reference.
            self.punch_clients[self.pipe_id] = puncher

            # Internal NAT prediction port allocator.
            self.nat_predict_alloc = NATPredictAlloc(stuns)
            self.nat_predict_alloc.set_nat_info(
                self.src_info["nat"], self.dest_info["nat"]
            )
            self.nat_predict_alloc.set_punch_mode(
                self.same_machine, self.dest_info["ip"]
            )

            # Schedule punching with a delay to allow for updated mappings.
            # Done like this because a new message may or may not come.
            if self.pipe_id not in self.punch_proc:
                self.pipes[self.pipe_id] = asyncio.Future()
                self.punch_proc[self.pipe_id] = asyncio.create_task(
                    self.delayed_start_punching_proc(self.nic, puncher)
                )

        # Extract any received payload attributes.
        if reply is not None:
            recv_mappings = reply.payload.mappings
            recv_mappings = [NATMapping(m) for m in recv_mappings]
            assert(recv_mappings)
        else:
            recv_mappings = None

        # Update details needed for TCP punching.
        port_alloc, is_end = await self.nat_predict_alloc.port_alloc(recv_mappings)
        puncher.port_allocs = port_alloc
        print(puncher.port_allocs)
        
        # Protocol done -- return nothing.
        if is_end == 1:
            return

        # Increase active punchers.
        #self.active_punchers += 1

        # Forward protocol details to peer.
        mappings = []
        for m in self.nat_predict_alloc.send_mappings:
            mappings.append(m.toJSON())

        # Protocol layer fills in meta and routing info.
        msg = PunchMsg({
            "payload": {
                "punch_mode": self.nat_predict_alloc.punch_mode,
                "mappings": mappings,
                "ntp": timestamp,
            },
        })

        msg.meta.plugin_name = "punch"
        await self.signal_msg_sender(msg)


class PunchPluginFactory():
    def __init__(self, stun_clients, punch_clients, sys_clock=SysClock(None, Dec("0.1")), proc_pool=None):
        self.stun_clients = stun_clients # af if index
        self.sys_clock = sys_clock
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
        
async def tcp_punch_cleanup(tunnel, af, pipe_id, src_info, dest_info, nic, addr_type, reply=None):
    tunnel.node.active_punchers = max(
        0,
        tunnel.node.active_punchers - 1
    )

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

    sys_clock = SysClock(nic, Dec("0.1"))
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

if __name__ == "__main__":
    async_run(workspace())

