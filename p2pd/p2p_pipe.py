import asyncio
from .address import Address
from .pipe_utils import pipe_open
from .p2p_addr import *
from .tcp_punch import TCP_PUNCH_UPDATE_RECIPIENT_MAPPINGS
from .tcp_punch import TCP_PUNCH_IN_MAP
from .p2p_utils import for_addr_infos, get_turn_client
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
            print("reply is none {node}")
            self.pipe_id = to_s(rand_plain(15))
        else:
            print("reply is not none {node}")
            self.pipe_id = to_s(reply.meta.pipe_id)

        print(f"using {self.pipe_id}")
        self.node.pipe_future(self.pipe_id)
        self.msg_queue = asyncio.Queue()
        self.msg_dispatcher_done = asyncio.Event()
        self.msg_dispatcher_task = None

        # Mapping for funcs over addr infos.
        # Loop over the most likely strategies left.
        self.func_table = [
            # Short timeouts for direct TCP cons.
            [self.direct_connect, 5, None],
            [self.reverse_connect, 5, None],

            # Large timeout for meetings with a state cleanup.
            [self.tcp_hole_punch, 40, self.tcp_punch_cleanup],

            # Large timeout, end refreshers, disable LAN cons.
            [self.udp_turn_relay, 20, self.turn_cleanup],
        ]

    async def cleanup(self):
        if self.msg_dispatcher_task is None:
            return
        
        print("in p2p pipe cleanup")
        self.msg_queue.put_nowait(None)
        self.msg_dispatcher_task.cancel()
        self.msg_dispatcher_task = None
        print("p2p pipe cleanup done.")

    async def msg_dispatcher(self):
        try:
            msg = await self.msg_queue.get()
            if msg is None:
                self.msg_dispatcher_done.set()
                print("One connect finished.")
                return
            
            await self.node.await_peer_con(
                msg,
                self.dest,
            )

            self.msg_dispatcher_task = asyncio.ensure_future(
                self.msg_dispatcher()
            )
        except RuntimeError:
            what_exception()
            print("msg dispatcher urntime error.")
            return

    async def connect(self, strategies=P2P_STRATEGIES):
        # Route messages to destination.
        if self.msg_dispatcher_task is None:
            self.msg_dispatcher_task = asyncio.ensure_future(
                self.msg_dispatcher()
            )

        # Try strategies to achieve a connection.
        strats = [P2P_DIRECT, P2P_REVERSE, P2P_PUNCH, P2P_RELAY]
        for i, strategy in enumerate(strats):


            # ... But still need to respect their choices.
            if strategy not in strategies:
                continue

            # Returns a msg given a comp addr info pair.
            index = strategy - 1
            print(index)
            func, timeout, cleanup = self.func_table[index]
            pipe = await for_addr_infos(
                self.src,
                self.dest,
                func,
                timeout,
                cleanup,
                self,
            )

            print(f"In connect pipe = {pipe}")
            
            # Strategy failed so continue.
            if pipe is None:
                print(f"strat {strategy} failed")
                continue

            # NOP -- don't process this result.
            if pipe == 1:
                await self.cleanup()
                return

            """
            # Ensure node protocol handler setup on pipe.
            if self.node.msg_cb not in pipe.msg_cbs:
                pipe.add_msg_cb(self.node.msg_cb)
            """

            await self.cleanup()
            return pipe

        await self.cleanup()
            
    async def direct_connect(self, af, src_info, dest_info, iface, addr_type):
        # Connect to this address.
        dest = Address(
            dest_info["ip"],
            dest_info["port"],
        )

        # (1) Get first interface for AF.
        # (2) Build a 'route' from it with it's main NIC IP.
        # (3) Bind to the route at port 0. Return itself.
        route = await iface.route(af).bind()

        # Connect to this address.
        dest = Address(
            str(dest_info["ip"]),
            dest_info["port"],
        )

        pipe = await pipe_open(
            route=route,
            proto=TCP,
            dest=dest,
            msg_cb=node_protocol,
        )

        if pipe is None:
            return

        await pipe.send(to_b(f"ID {self.pipe_id}"))
        self.node.pipe_ready(self.pipe_id, pipe)

        return pipe

    async def reverse_connect(self, af, src_info, dest_info, iface, addr_type):
        print("in reverse connect")
        msg = ConMsg({
            "meta": {
                "af": af,
                "pipe_id": self.pipe_id,
                "src_buf": self.src_bytes,
                "src_index": src_info["if_index"],
                "addr_types": [addr_type],
            },
            "routing": {
                "af": af,
                "dest_buf": self.dest_bytes,
                "dest_index": dest_info["if_index"],
            },
        })

        self.msg_queue.put_nowait(msg)
        return await self.node.pipes[self.pipe_id]

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
    async def tcp_hole_punch(self, af, src_info, dest_info, iface, addr_type):
        # Punch clients indexed by interface offset.
        if_index = src_info["if_index"]
        punch = self.node.tcp_punch_clients[if_index]
        stun_client = self.node.stun_clients[af][if_index]

        print(f"Punch pipe id = {self.pipe_id}")
        print(f'{self.dest["node_id"]}')
        print("trying tcp punch method")

        punch_mode, punch_state, punch_ret = await punch.proto_update(
            af,
            str(dest_info["ip"]),
            dest_info["nat"],
            self.dest["node_id"],
            self.pipe_id,
            stun_client,
            iface,
            same_machine=self.same_machine,
            reply=self.reply,
        )

        print(f"punch state = {punch_state}")

        # End protocol.
        if punch_state is None:
            print("punch ret is none")
            return 1
        
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
                "addr_types": [addr_type],
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
        self.msg_queue.put_nowait(msg)

        # Basic dest addr validation.
        #msg.set_cur_addr(self.src_bytes)
        msg.routing.load_if_extra(self.node)
        msg.validate_dest(af, punch_mode, str(dest_info["ip"]))

        # Prevent protocol loop.
        return await self.node.pipes[self.pipe_id]

    # TODO improve this code?
    async def udp_turn_relay(self, af, src_info, dest_info, iface, addr_type):
        if addr_type == NIC_BIND:
            return None

        print("in p2p pipe udp relay")
        print(f"{self.reply is not None}")
        peer_tup = relay_tup = None
        dest_peer = dest_relay = turn_client = None

        # Try TURN servers in random order.
        offsets = list(range(0, len(TURN_SERVERS)))
        random.shuffle(offsets)
        if self.reply is not None:
            offsets = [self.reply.payload.serv_id]
            dest_peer = self.reply.payload.peer_tup
            dest_relay = self.reply.payload.relay_tup

        print(self.node.turn_clients)
        print(self.pipe_id)

        # Attempt to connect to TURN server.
        for offset in offsets:
            try:
                # Attempt to load a TURN client.
                if self.pipe_id not in self.node.turn_clients:
                    print(f"{self.pipe_id} not in turn clients {self.node.turn_clients}")
                    peer_tup, relay_tup, turn_client = await get_turn_client(
                        af,
                        offset,
                        iface,
                        dest_peer=dest_peer,
                        dest_relay=dest_relay,
                    )

                    # Load TURN client failed.
                    if turn_client is None:
                        continue

                    self.node.turn_clients[self.pipe_id] = turn_client
                else:
                    turn_client = self.node.turn_clients[self.pipe_id]

                if self.reply is not None:
                    print("reply is not none in turn ")
                    print(f"{dest_peer} {turn_client.peers}")

                    # TURN request.
                    if tuple(dest_peer) not in turn_client.peers:
                        print("in turn client accept peer")
                        print(peer_tup)
                        print(relay_tup)
                        await turn_client.accept_peer(
                            dest_peer,
                            dest_relay,
                        )

                        self.node.pipe_ready(self.pipe_id, turn_client)

                        # Protocol end.
                        return 1
                    else:
                        self.node.pipe_ready(self.pipe_id, turn_client)

                # Return a new TURN request.
                msg = TURNMsg({
                    "meta": {
                        "pipe_id": self.pipe_id,
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
                        "peer_tup": peer_tup,
                        "relay_tup": relay_tup,
                        "serv_id": offset,
                    },
                })
                print(msg)
                self.msg_queue.put_nowait(msg)
                return await self.node.pipes[self.pipe_id]
            except:
                log_exception()
                continue

    def general_cleanup(self):
        self.reply = None
        del self.node.pipes[self.pipe_id]
        self.node.pipe_future(self.pipe_id)

    async def tcp_punch_cleanup(self, af, src_info, dest_info, iface, addr_type):
        print("in tcp punch cleanup")
        self.general_cleanup()
        node_id = self.dest["node_id"]
        if_index = src_info["if_index"]
        client = self.node.tcp_punch_clients[if_index]
        await client.cleanup_state(node_id, self.pipe_id)
        print(client.state)
        print(self.msg_dispatcher_task)

    async def turn_cleanup(self, af, src_info, dest_info, iface, addr_type):
        self.general_cleanup()
        if self.pipe_id not in self.node.turn_clients:
            return
        
        turn_client = self.node.turn_clients[self.pipe_id]
        await turn_client.close()
        del self.node.turn_clients[self.pipe_id]


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