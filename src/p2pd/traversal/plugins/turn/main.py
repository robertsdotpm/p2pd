from ....net.net import *
from ....net.pipe.pipe_utils import PipeEvents
from ....settings import *
from ....utility.utils import *
from ....traversal.signaling.signaling_msgs import TURNMsg
from ....node.node_utils import get_first_working_turn_client

async def udp_turn_relay(self, af, pipe_id, src_info, dest_info, iface, addr_type, reply=None):
    if addr_type == NIC_BIND:
        return None
    
    # Load TURN client for this PIPE ID.
    if pipe_id in self.node.turn_clients:
        client = self.node.turn_clients[pipe_id]
    else:
        # Use these TURN servers.
        offsets = list(range(0, len(TURN_SERVERS)))
        random.shuffle(offsets)
        if reply is not None:
            offsets = [reply.payload.serv_id]

        # Use first server from offsets that works.
        client = await get_first_working_turn_client(
            af,
            offsets,
            iface,
            self.node.msg_cb
        )

        # Save client reference.
        self.node.turn_clients[pipe_id] = client

    # Extract any received payload attributes.
    if reply is not None:
        dest_peer = reply.payload.peer_tup
        dest_relay = reply.payload.relay_tup
        already_accepted = await client.accept_peer(
            dest_peer,
            dest_relay,
        )

        # Indicate client ready to waiters.
        self.node.pipe_ready(pipe_id, client)

        # Protocol end.
        if already_accepted:
            return PipeEvents(None)
        else:
            # Log white listing action.
            our_relay = await client.relay_tup_future
            m = fstr("Whitelist {0} -> {1} to", (dest_peer, our_relay,))
            m += fstr(" '{0}'", (iface.name,))
            Log.log_p2p(m, self.node.node_id[:8])

    # Return a new TURN request.
    msg = TURNMsg({
        "meta": {
            "ttl": int(self.node.sys_clock.time()) + 30,
            "pipe_id": pipe_id,
            "af": af,
            "src_buf": self.src_bytes,
            "src_index": src_info["if_index"],
            "addr_types": [addr_type],
        },
        "routing": {
            "af": af,
            "dest_buf": self.dest_bytes,
            "dest_index": dest_info["if_index"],
        },
        "payload": {
            "peer_tup": await client.client_tup_future,
            "relay_tup": await client.relay_tup_future,
            "serv_id": client.serv_offset,
        },
    })

    #dest_node_id = self.dest["node_id"]
    #dest_pkc = self.node.auth[dest_node_id]["vk"]
    #self.node.sig_msg_queue.put_nowait([msg, dest_pkc , 1])

    try:
        self.route_msg(msg, reply=reply, m=3)
        return await self.node.pipes[pipe_id]
    except:
        log_exception()

async def turn_cleanup(self, af, pipe_id, src_info, dest_info, iface, addr_type, reply=None):
    if pipe_id not in self.node.turn_clients:
        return

    turn_client = self.node.turn_clients[pipe_id]
    await turn_client.close()
    del self.node.turn_clients[pipe_id]