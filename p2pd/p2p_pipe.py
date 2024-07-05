import asyncio
from .p2p_addr import *
from .tcp_punch import *
from .turn_client import *
from .signaling import *
from .p2p_utils import *
from .p2p_protocol import *

"""
TCP 
nc -4 -l 127.0.0.1 10001 -k
nc -6 -l ::1 10001 -k
"""

P2P_DIRECT = 1
P2P_REVERSE = 2
P2P_PUNCH = 3
P2P_RELAY = 4

# TURN is not included as a default strategy because it uses UDP.
# It will need a special explanation for the developer.
# SOCKS might be a better protocol for relaying in the future.
P2P_STRATEGIES = [P2P_DIRECT, P2P_REVERSE, P2P_PUNCH]

class P2PPipe():
    def __init__(self, node):
        self.node = node
        self.tasks = []
    
    async def connect(self, dest_bytes, strategies=P2P_STRATEGIES):
        # Create a future for pending pipes.
        pipe_id = self.node.pipe_future(pipe_id)
        pipe = None

        # Attempt direct connection first.
        # The only method not to need signal messages.
        if P2P_DIRECT in strategies:
            # TODO: patch dest 
            pipe = await direct_connect(
                pipe_id,
                dest_bytes,
                self.node
            )

            if pipe is not None:
                return self.node.pipe_ready(pipe_id, pipe)

        # Proceed only if they need signal messages.
        if strategies == [P2P_DIRECT]:
            return None
        
        # Used to relay signal proto messages.
        peer_dest = parse_peer_addr(dest_bytes)
        signal_pipe = self.node.find_signal_pipe(peer_dest)
        if signal_pipe is None:
            signal_pipe = await new_peer_signal_pipe(
                peer_dest,
                self.node
            )
            assert(signal_pipe is not None)

        # Try reverse connect.
        msg = self.reverse_connect(pipe_id, dest_bytes)
        pipe = await self.node.await_peer_con(msg, signal_pipe, 5)

        # Successful reverse connect.
        if pipe is not None:
            return self.node.pipe_ready(pipe_id, pipe)

        # Mapping for funcs over addr infos.
        # Loop over the most likely strategies left.
        func_table = [self.tcp_hole_punch, self.udp_relay],
        for i, strategy in enumerate([P2P_PUNCH, P2P_RELAY]):
            # ... But still need to respect their choices.
            if strategy not in strategies:
                continue

            # Returns a message from func given a comp addr info pair.
            msg = await for_addr_infos(
                pipe_id,
                self.node.addr_bytes,
                dest_bytes,
                func_table[i],
            )

            # If no signal message returned then skip.
            if msg is not None:
                pipe = await self.node.await_peer_con(msg, signal_pipe)

            # Success so return
            if pipe is not None:
                return pipe

    async def reverse_connect(self, af, pipe_id, node_id, src_info, dest_info, dest_bytes, same_machine=False):
        print("in reverse connect")
        return ConMsg({
            "meta": {
                "af": af,
                "pipe_id": pipe_id,
                "src_buf": self.node.addr_bytes,
                "src_index": src_info["if_index"],
            },
            "routing": {
                "af": af,
                "dest_buf": dest_bytes,
                "dest_index": dest_info["if_index"],
            },
        })

    """
    Peer A and peer B both have a list of interface info
    for each address family. Each interface connected to
    a unique gateway will have its own NAT characteristics.
    The challenge is to prioritize which combination of
    peer interfaces is most favorable given the interplay
    between their corresponding NAT qualities.

    The least restrictive NATs are assigned a lower
    value. So the start of the algorithm just groups together
    the lowest value pairs and runs through them until one
    succeeds.
    """
    async def tcp_hole_punch(self, af, pipe_id, node_id, src_info, dest_info, dest_bytes, same_machine=False):
        # Punch clients indexed by interface offset.
        if_index = src_info["if_index"]
        interface = self.node.ifs[if_index]
        initiator = self.node.tcp_punch_clients[if_index]
        patched_p2p = work_behind_same_router(
            self.node.p2p_addr,
            parse_peer_addr(dest_bytes),
        )

        # Select [ext or nat] dest and punch mode
        # (either local, self, remote)
        punch_mode, use_addr = await get_punch_mode(
            af,
            patched_p2p[af][dest_info["if_index"]],
            interface,
            initiator,
            same_machine,
        )

        print("alice punch mode")
        print(punch_mode)
        print(use_addr)
        print(f"open pipe same = {same_machine}")

        # Get initial NAT predictions using STUN.
        stun_client = self.node.stun_clients[af][if_index]
        punch_ret = await initiator.proto_send_initial_mappings(
            use_addr,
            dest_info["nat"],
            node_id,
            pipe_id,
            stun_client,
            mode=punch_mode,
            same_machine=same_machine,
        )

        """
        Punching is delayed for a few seconds to
        ensure there's enough time to receive any
        updated mappings for the dest peer (if any.)
        """
        asyncio.ensure_future(
            self.node.schedule_punching_with_delay(
                if_index,
                pipe_id,
                node_id,
            )
        )

        # Initial step 1 punch message.
        msg = TCPPunchMsg({
            "meta": {
                "pipe_id": pipe_id,
                "af": af,
                "src_buf": self.node.addr_bytes,
                "src_index": 0,
            },
            "routing": {
                "af": af,
                "dest_buf": dest_bytes,
                "dest_index": 0,
            },
            "payload": {
                "punch_mode": punch_mode,
                "ntp": punch_ret[1],
                "mappings": punch_ret[0],
            },
        })

        # Basic dest addr validation.
        msg.set_cur_addr(self.node.addr_bytes)
        msg.routing.load_if_extra(self.node)
        msg.validate_dest(af, punch_mode, use_addr)
        return msg

    async def udp_relay(self, af, pipe_id, node_id, src_info, dest_info, dest_bytes, same_machine=False):
        # Try TURN servers in random order.
        offsets = list(range(0, len(TURN_SERVERS)))
        random.shuffle(offsets)

        # Attempt to connect to TURN server.
        peer_tup = relay_tup = turn_client = None
        for offset in offsets:
            try:
                peer_tup, relay_tup, turn_client = await get_turn_client(
                    af,
                    offset,
                    self.node.ifs[src_info["if_index"]]
                )
            except:
                log_exception()
                continue

            if turn_client is not None:
                self.node.pipe_future(pipe_id)
                self.node.turn_clients[pipe_id] = turn_client
                return TURNMsg({
                    "meta": {
                        "pipe_id": pipe_id,
                        "af": af,
                        "src_buf": self.node.addr_bytes,
                        "src_index": src_info["if_index"],
                    },
                    "routing": {
                        "af": af,
                        "dest_buf": dest_bytes,
                        "dest_index": dest_info["if_index"],
                    },
                    "payload": {
                        "peer_tup": peer_tup,
                        "relay_tup": relay_tup,
                        "serv_id": offset,
                    },
                })

if __name__ == "__main__": # pragma: no cover
    async def test_p2p_con():
        p2p_dest = None
        if1 = await Interface("enp3s0").start()
        if_list = [if1]
        pipe_id = rand_plain(10)
        p2p_pipe = P2PPipe(if_list, 0)
        await p2p_pipe.direct_connect(p2p_dest, pipe_id, proto=TCP)


        while 1:
            await asyncio.sleep(1)

    async_test(test_p2p_con)