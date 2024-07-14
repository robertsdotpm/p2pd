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

class P2PPipe():
    def __init__(self, dest_bytes, node, reply=None, conf=P2P_PIPE_CONF):
        # Record main references.
        self.conf = conf
        self.node = node
        self.reply = reply

        # Parse address bytes to dicts.
        self.dest_bytes = dest_bytes
        self.dest = parse_peer_addr(dest_bytes)
        self.src  = self.node.p2p_addr
        self.src_bytes = self.node.addr_bytes
        
        # Is this a connection to a node on the same machine?
        if self.dest["machine_id"] == self.src["machine_id"]:
            self.same_machine = True
        else:
            self.same_machine = False

        # Create a future for pending pipes.
        if reply is None:
            self.pipe_id = to_s(rand_plain(15))
        else:
            self.pipe_id = to_s(reply.meta.pipe_id)

        self.node.pipe_future(self.pipe_id)

    async def connect(self, strategies=P2P_STRATEGIES):
        # Attempt direct connection first.
        # The only method not to need signal messages.
        if P2P_DIRECT in strategies:
            # Returns a message from func given a comp addr info pair.
            pipe = await for_addr_infos(
                self.src,
                self.dest,
                self.direct_connect,
                self,
            )

            if pipe is not None:
                return pipe

        # Proceed only if they need signal messages.
        if strategies == [P2P_DIRECT]:
            return None
        
        """
        # Used to relay signal proto messages.
        signal_pipe = self.node.find_signal_pipe(dest)
        if signal_pipe is None:
            signal_pipe = await new_peer_signal_pipe(
                dest,
                self.node
            )
            assert(signal_pipe is not None)
        """
        signal_pipe = None

        # Try reverse connect.
        if P2P_REVERSE in strategies:
            msg = await for_addr_infos(
                self.src,
                self.dest,
                self.reverse_connect,
                self,
            )

            if self.conf["return_msg"]: return msg
            pipe = await self.node.await_peer_con(msg, signal_pipe, 5)

            # Successful reverse connect.
            if pipe is not None:
                return self.node.pipe_ready(self.pipe_id, pipe)
            
        # Mapping for funcs over addr infos.
        # Loop over the most likely strategies left.
        func_table = [self.tcp_hole_punch, self.udp_relay]
        for i, strategy in enumerate([P2P_PUNCH, P2P_RELAY]):
            # ... But still need to respect their choices.
            if strategy not in strategies:
                continue

            # Returns a message from func given a comp addr info pair.
            msg = await for_addr_infos(
                self.src,
                self.dest,
                func_table[i],
                self,
            )

            # If no signal message returned then skip.
            if msg is not None:
                if self.conf["return_msg"]: return msg

                pipe = await self.node.await_peer_con(msg, signal_pipe)
                if pipe is not None:
                    return pipe
            
    async def direct_connect(self, af, src_info, dest_info, interface):
        # Connect to this address.
        dest = Address(
            dest_info["ip"],
            dest_info["port"],
        )

        # (1) Get first interface for AF.
        # (2) Build a 'route' from it with it's main NIC IP.
        # (3) Bind to the route at port 0. Return itself.
        route = await interface.route(af).bind()
        print("in make con")
        print(dest_info["ip"])
        print(dest_info["port"])

        # Connect to this address.
        dest = Address(
            str(dest_info["ip"]),
            dest_info["port"],
        )

        print(route._bind_tups)
        print(dest.host)

        pipe = await pipe_open(
            route=route,
            proto=TCP,
            dest=dest,
            msg_cb=self.node.msg_cb
        )

        if pipe is None:
            return

        await pipe.send(to_b(f"ID {self.pipe_id}"))

        print(pipe)
        return pipe

    async def reverse_connect(self, af, src_info, dest_info, interface):
        print("in reverse connect")
        return ConMsg({
            "meta": {
                "af": af,
                "pipe_id": self.pipe_id,
                "src_buf": self.src_bytes,
                "src_index": src_info["if_index"],
                "addr_types": self.conf["addr_types"],
            },
            "routing": {
                "af": af,
                "dest_buf": self.dest_bytes,
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
    async def tcp_hole_punch(self, af, src_info, dest_info, interface):
        # Punch clients indexed by interface offset.
        if_index = src_info["if_index"]
        punch = self.node.tcp_punch_clients[if_index]
        stun_client = self.node.stun_clients[af][if_index]
        punch_mode, punch_state, punch_ret = await punch.proto_update(
            af,
            str(dest_info["ip"]),
            dest_info["nat"],
            self.dest["node_id"],
            self.pipe_id,
            stun_client,
            interface,
            same_machine=self.same_machine,
            reply=self.reply,
        )

        if punch_ret is None:
            print("punch ret is none")
            return

        """
        Punching is delayed for a few seconds to
        ensure there's enough time to receive any
        updated mappings for the dest peer (if any.)
        """
        asyncio.ensure_future(
            self.node.schedule_punching_with_delay(
                if_index,
                self.pipe_id,
                self.dest["node_id"],
                2 if punch_state == TCP_PUNCH_IN_MAP else 0
            )
        )

        print("after schedule punch")


        msg = TCPPunchMsg({
            "meta": {
                "pipe_id": self.pipe_id,
                "af": af,
                "src_buf": self.src_bytes,
                "src_index": src_info["if_index"],
                "addr_types": self.conf["addr_types"],
            },
            "routing": {
                "af": af,
                "dest_buf": self.dest_bytes,
                "dest_index": dest_info["if_index"],
            },
            "payload": {
                "punch_mode": punch_mode,
                "ntp": punch_ret[1],
                "mappings": punch_ret[0],
            },
        })

        # Basic dest addr validation.
        msg.set_cur_addr(self.src_bytes)
        msg.routing.load_if_extra(self.node)
        msg.validate_dest(af, punch_mode, str(dest_info["ip"]))
        return msg

    async def udp_relay(self, af, src_info, dest_info, interface):
        print("in p2p pipe udp relay")
        print(f"{self.reply is not None}")
        peer_tup = relay_tup = turn_client = None

        # Try TURN servers in random order.
        offsets = list(range(0, len(TURN_SERVERS)))
        random.shuffle(offsets)
        if self.reply is not None:
            offsets = [self.reply.payload.serv_id]
            peer_tup = self.reply.payload.peer_tup
            relay_tup = self.reply.payload.relay_tup

        print(self.node.turn_clients)
        print(self.pipe_id)

        # Attempt to connect to TURN server.
        for offset in offsets:
            try:
                if self.pipe_id in self.node.turn_clients:
                    turn_client = self.node.turn_clients[self.pipe_id]
                    print("in turn client accept peer")
                    print(peer_tup)
                    print(relay_tup)
                    if peer_tup is not None:
                        await turn_client.accept_peer(
                            peer_tup,
                            relay_tup,
                        )
                else:
                    peer_tup, relay_tup, turn_client = await get_turn_client(
                        af,
                        offset,
                        interface,
                        dest_peer=peer_tup,
                        dest_relay=relay_tup,
                    )

                if self.reply is not None:
                    self.node.pipe_ready(self.pipe_id, turn_client)
            except:
                log_exception()
                continue

            if turn_client is not None:
                self.node.turn_clients[self.pipe_id] = turn_client
                return TURNMsg({
                    "meta": {
                        "pipe_id": self.pipe_id,
                        "af": af,
                        "src_buf": self.src_bytes,
                        "src_index": src_info["if_index"],
                        "addr_types": self.conf["addr_types"],
                    },
                    "routing": {
                        "af": af,
                        "dest_buf": self.dest_bytes,
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