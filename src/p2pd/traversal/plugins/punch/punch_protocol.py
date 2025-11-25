from ....utility.utils import *
from ....net.net_utils import *
from ....nic.nat.nat_predict import *
from ...signaling.signal_msgs import PunchMsg, DoneMsg
from .punch_defs import *
from .utility.punch_utils import *
from .punch import *
from .port_allocators.nat_predict_alloc import *
from .punch_process import *

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

class PunchProtocol():
    def __init__(self, stun_clients, sys_clock=SysClock(None, Dec("0.1")), proc_pool=None):
        self.stun_clients = stun_clients # af if index
        self.sys_clock = sys_clock
        self.proc_pool = proc_pool
        self.punch_clients = {}
        self.punch_proc = {} # pipe_id: delayed start punching proc task
        self.active_punchers = 0

    async def delayed_start_punching_proc(self, nic, puncher):
        # Give time for updated mappings.
        await asyncio.sleep(3)
        await start_punching_process(nic, puncher, self.proc_pool)

    async def protocol(self, pp=None, af=IP4, pipe_id=b"pipe", src_info=None, dest_info=None, nic=None, addr_type=NIC_BIND, same_machine=False, reply=None):
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
            
            # Figure out addressing for sockets.
            # Dest IP runs select dest IPR to contextually determine best IP.
            route = await nic.bind(af)
            dest_ip = dest_info["ip"]
            if "fe80" == dest_ip:
                src_ip = str(route.link_locals[0])
            else:
                src_ip = route.nic()

            # Create a new puncher for this pipe ID.
            puncher = Punch(dest_ip, src_ip, route.exe())

            # Set current unix time using NTP as a reference.
            timestamp = self.sys_clock.time()
            puncher.set_timestamp(timestamp)

            # Set future punching time.
            punch_time = reply.payload.ntp if reply else timestamp + 10
            puncher.set_punch_time(punch_time)

            # Save puncher reference.
            self.punch_clients[pipe_id] = puncher

            # Internal NAT prediction port allocator.
            puncher.nat_predict_alloc = NATPredictAlloc(stuns)
            puncher.nat_predict_alloc.set_nat_info(
                src_info["nat"], dest_info["nat"]
            )
            puncher.nat_predict_alloc.set_punch_mode(
                same_machine, dest_info["ip"]
            )

            # Schedule punching proc with a delay to allow for updated mappings.
            # Done like this because a new message may or may not come.
            if pipe_id not in self.punch_proc:
                self.punch_proc[pipe_id] = asyncio.create_task(
                    self.delayed_start_punching_proc(nic, puncher)
                )

        # Extract any received payload attributes.
        if reply is not None:
            recv_mappings = reply.payload.mappings
            recv_mappings = [NATMapping(m) for m in recv_mappings]
            assert(recv_mappings)
        else:
            recv_mappings = None

        # Update details needed for TCP punching.
        _, is_end = await puncher.nat_predict_alloc.port_alloc(recv_mappings)
        
        # Protocol done -- return nothing.
        if is_end == 1:
            return DoneMsg()

        # Increase active punchers.
        self.active_punchers += 1

        # Forward protocol details to peer.
        mappings = [m.toJSON() for m in puncher.nat_predict_alloc.send_mappings]

        # Protocol layer fills in meta and routing info.
        # TODO: protocol layer now has to fill in meta and routing info.
        msg = PunchMsg({
            "payload": {
                "punch_mode": puncher.nat_predict_alloc.punch_mode,
                "mappings": mappings,
                "ntp": punch_time,
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

