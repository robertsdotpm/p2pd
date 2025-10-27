from ....utility.utils import *
from ....net.net import *
from ....net.pipe.pipe_utils import PipeEvents
from ....nic.nat.nat_predict import *
from ...signaling.signaling_msgs import TCPPunchMsg
from .tcp_punch_client import *

async def tcp_hole_punch(tunnel, af, pipe_id, src_info, dest_info, nic, addr_type, reply=None):
    # Load TCP punch client for this pipe ID.
    if pipe_id in tunnel.node.tcp_punch_clients:
        puncher = tunnel.node.tcp_punch_clients[pipe_id]
        assert(src_info == puncher.src_info)
        if dest_info != puncher.dest_info:
            """
            If an address fetch gets an old address a node replies
            with its current address info in a reply which
            is passed back to this function.
            """
            tunnel.node.log("p2p", fstr("<punch> Updating dest info {0}", (dest_info,)))
            puncher.dest_info = dest_info
    else:
        # Create a new puncher for this pipe ID.
        if_index = src_info["if_index"]
        stuns = tunnel.node.stun_clients[af][if_index]

        # Skip if no STUN clients loaded.
        if not len(stuns):
            return None
        
        # Create a new puncher for this pipe ID.
        puncher = TCPPuncher(
            af,
            src_info,
            dest_info,
            stuns,
            tunnel.node.sys_clock,
            nic,
            tunnel.same_machine,
        )

        # Save a reference to node.
        puncher.set_parent(pipe_id, tunnel.node)

        # Setup process manager and executor.
        # So that objects are shareable over processes.
        puncher.setup_multiproc(tunnel.node.pp_executor)

        # Save puncher reference.
        tunnel.node.tcp_punch_clients[pipe_id] = puncher

    # Extract any received payload attributes.
    if reply is not None:
        recv_mappings = reply.payload.mappings
        recv_mappings = [NATMapping(m) for m in recv_mappings]
        start_time = reply.payload.ntp
        assert(recv_mappings)
    else:
        recv_mappings = None
        start_time = None

    # Update details needed for TCP punching.
    ret = await puncher.proto(
        recv_mappings,
        start_time,
    )
    
    # Protocol done -- return nothing.
    if ret == 1:
        return PipeEvents(None)

    # Increase active punchers.
    tunnel.node.active_punchers = min(
        tunnel.node.max_punchers,
        tunnel.node.active_punchers + 1
    )

    """
    Punching is delayed for a few seconds to
    ensure there's enough time to receive any
    updated mappings for the dest peer (if any.)
    """
    task = create_task(
        schedule_punching_with_delay(
            tunnel.node,
            pipe_id,
            n=2 if puncher.side == INITIATOR else 0
        )
    )
    tunnel.node.tasks.append(task)

    # Forward protocol details to peer.
    mappings = [m.toJSON() for m in ret[0]]
    msg = TCPPunchMsg({
        "meta": {
            "ttl": int(tunnel.node.sys_clock.time()) + 30,
            "pipe_id": pipe_id,
            "af": af,
            "src_buf": tunnel.src_bytes,
            "src_index": src_info["if_index"],
            "addr_types": [addr_type],
        },
        "routing": {
            "af": af,
            "dest_buf": tunnel.dest_bytes,
            "dest_index": dest_info["if_index"],
        },
        "payload": {
            "punch_mode": puncher.punch_mode,
            "ntp": ret[1],
            "mappings": mappings,
        },
    })

    #self.route_msg(msg, reply=reply, m=2)
    #dest_node_id = self.dest["node_id"]
    #dest_pkc = self.node.auth[dest_node_id]["vk"]
    """
    if reply is None:
        dest_node_id = self.dest["node_id"]
        dest_pkc = self.node.auth[dest_node_id]["vk"]
    else:
        #dest_pkc = h_to_b(reply.cipher.vk)

        print(reply.cipher.vk)
    """

    tunnel.node.sig_msg_queue.put_nowait([msg, None , 2])

    # Prevent protocol loop.
    pipe = await tunnel.node.pipes[pipe_id]

    # Watch this pipe for idleness.
    tunnel.node.last_recv_table[pipe.sock] = time.time()
    tunnel.node.last_recv_queue.append(pipe)

    # Close pipe if ping times out.
    return pipe

async def tcp_punch_cleanup(tunnel, af, pipe_id, src_info, dest_info, nic, addr_type, reply=None):
    tunnel.node.active_punchers = max(
        0,
        tunnel.node.active_punchers - 1
    )