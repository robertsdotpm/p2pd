"""
This function has too many references to Node which itself is a super manager object.
I shouldn't have to initiate a full node to test this.
Can the params take just what it needs. What would a pure, functional refactor
look like to make testing as easy as possible?

So something that introduces huge complexity: routing logic has been added
to every function. The functions should not need to care about the destination
addressing details. It should only focus on its own logic and returning a message
(if any), the routing layer can handle --filling in-- addresses.

same_machine should be set in the routing layer (and come in the message too)
"""

from ....utility.utils import *
from ....net.net_utils import *
from ....net.pipe.pipe_events import PipeEvents
from ....nic.nat.nat_predict import *
from ...signaling.signal_msgs import TCPPunchMsg
from .punch_defs import *
from .utility.punch_utils import *
from .punch import *
from .port_allocators.nat_predict_alloc import *

"""
tunnel.src_bytes,
src_info["if_index"],
[addr_type],
tunnel.dest_bytes,
dest_info["if_index"],
puncher.punch_mode,
tunnel.node.sig_msg_queue.put_nowait([msg, None , 2])

pipe = await tunnel.node.pipes[pipe_id]


        # Watch this pipe for idleness.
        tunnel.node.last_recv_table[pipe.sock] = time.time()
        tunnel.node.last_recv_queue.append(pipe)

    # Prevent protocol loop.
    pipe = await tunnel.node.pipes[pipe_id]

    # Watch this pipe for idleness.
    tunnel.node.last_recv_table[pipe.sock] = time.time()
    tunnel.node.last_recv_queue.append(pipe)

    # Close pipe if ping times out.
    return pipe
"""



class PunchProtocol():
    def __init__(self, stun_clients, sys_clock=SysClock(None, Dec("0.1")), proc_pool=None):
        self.stun_clients = stun_clients # af if index
        self.sys_clock = sys_clock
        self.proc_pool = proc_pool
        self.punch_clients = {}
        self.active_punchers = 0
        self.node = None
        self.tasks = []

    def set_node(self, node=None):
        self.node = node

    async def protocol(self, af=IP4, pipe_id=b"pipe", src_info=None, dest_info=None, nic=None, addr_type=NIC_BIND, same_machine=False, reply=None):
        # Load TCP punch client for this pipe ID.
        if pipe_id in self.punch_clients:
            puncher = self.punch_clients[pipe_id]
            assert(src_info == puncher.src_info)
            if dest_info != puncher.dest_info:
                """
                If an address fetch gets an old address a node replies
                with its current address info in a reply which
                is passed back to this function.
                """
                log("p2p" + fstr("<punch> Updating dest info {0}", (dest_info,)))
                puncher.dest_info = dest_info
        else:
            # Create a new puncher for this pipe ID.
            if_index = src_info["if_index"]
            stuns = self.stun_clients[af][if_index]

            # Skip if no STUN clients loaded.
            if not len(stuns):
                return None
            
            # Create a new puncher for this pipe ID.
            puncher = PunchPlugin(dest_info["ip"], src_info["ip"])
            puncher.set_routing(af, src_info, dest_info, nic)
            puncher.set_timestamp(self.sys_clock.time())

            # Save a reference to node.
            puncher.set_parent(pipe_id, self.node)

            # Setup process manager and executor.
            # So that objects are shareable over processes.
            puncher.setup_multiproc(self.proc_pool)

            # Save puncher reference.
            self.punch_clients[pipe_id] = puncher

            # Internal NAT prediction port allocator.
            puncher.nat_predict_alloc = NATPredictAlloc(stuns)
            puncher.nat_predict_alloc.set_punch_mode(
                same_machine,
                dest_info["ip"]
            )

        # Extract any received payload attributes.
        if reply is not None:
            recv_mappings = reply.payload.mappings
            recv_mappings = [NATMapping(m) for m in recv_mappings]
            assert(recv_mappings)
        else:
            recv_mappings = None

        # Update details needed for TCP punching.
        ret, is_end = await puncher.nat_predict_alloc.port_alloc(
            recv_mappings
        )
        
        # Protocol done -- return nothing.
        if is_end == 1:
            return PipeEvents(None)

        # Increase active punchers.
        self.active_punchers += 1

        """
        Punching is delayed for a few seconds to
        ensure there's enough time to receive any
        updated mappings for the dest peer (if any.)
        """

        """
        TODO:
        task = create_task(
            schedule_punching_with_delay(
                tunnel.node,
                pipe_id,
                n=2 if puncher.side == INITIATOR else 0
            )
        )
        self.tasks.append(task)
        """

        # Forward protocol details to peer.
        mappings = [m.toJSON() for m in puncher.nat_predict_alloc.send_mappings]

        """
        "meta": {
            #"ttl": int(self.sys_clock.time()) + 30,
            #"pipe_id": pipe_id,
            #"af": af,
            #"src_buf": tunnel.src_bytes,
            #"src_index": src_info["if_index"],
            #"addr_types": [addr_type],
        },
        "routing": {
            #"af": af,
            #"dest_buf": tunnel.dest_bytes,
            #"dest_index": dest_info["if_index"],
        },
        """

        # Protocol layer fills in meta and routing info.
        msg = TCPPunchMsg({
            "payload": {
                "punch_mode": puncher.nat_predict_alloc.punch_mode,
                "mappings": mappings,
            },
        })

        return msg

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
    punch_proto = PunchProtocol(
        stun_client_table, 
        proc_pool=proc_pool,
    )

    punch_proto.nic = nic
    return punch_proto

async def workspace():
    af = IP4
    punch_proto = await build_punch_proto(af)
    src_info = dest_info = {
        "if_index": 0,
        "ip": "127.0.0.1"
    }

    send_msg = await punch_proto.protocol(
        src_info=src_info,
        dest_info=dest_info,
        nic=punch_proto.nic,
        same_machine=True,
    )



    print(send_msg.to_dict())

if __name__ == "__main__":
    async_run(workspace())

