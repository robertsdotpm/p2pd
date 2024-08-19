import asyncio
from .address import Address
from .pipe_utils import pipe_open
from .p2p_addr import *
from .tcp_punch import TCP_PUNCH_IN_MAP
from .p2p_utils import for_addr_infos, get_turn_client
from .p2p_protocol import *

"""
TCP 
nc -4 -l 127.0.0.1 10001 -k
nc -6 -l ::1 10001 -k
"""

class P2PPipe():
    def __init__(self, dest_bytes, node):
        # Record main references.
        self.node = node

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

        self.msg_queue = asyncio.Queue()
        self.msg_dispatcher_done = asyncio.Event()
        self.msg_dispatcher_task = None

        # Mapping for funcs over addr infos.
        # Loop over the most likely strategies left.
        self.func_table = {
            # Short timeouts for direct TCP cons.
            P2P_DIRECT: [self.direct_connect, 5, None],
            P2P_REVERSE: [self.reverse_connect, 5, None],

            # Large timeout for meetings with a state cleanup.
            P2P_PUNCH: [self.tcp_hole_punch, 40, self.tcp_punch_cleanup],

            # Large timeout, end refreshers, disable LAN cons.
            P2P_RELAY: [self.udp_turn_relay, 20, self.turn_cleanup],
        }

    async def cleanup(self):
        if self.msg_dispatcher_task is None:
            return
        
        self.msg_queue.put_nowait(None)
        self.msg_dispatcher_task.cancel()
        self.msg_dispatcher_task = None

    async def msg_dispatcher(self):
        try:
            msg = await self.msg_queue.get()
            if msg is None:
                self.msg_dispatcher_done.set()
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
            return

    async def connect(self, strategies=P2P_STRATEGIES, reply=None, conf=P2P_PIPE_CONF):
        # Route messages to destination.
        if self.msg_dispatcher_task is None:
            self.msg_dispatcher_task = asyncio.ensure_future(
                self.msg_dispatcher()
            )

        # Try strategies to achieve a connection.
        for strategy in strategies:
            # Skip invalid strategy.
            if strategy not in self.func_table:
                continue

            # Returns a pipe given comp addr info pairs.
            func, timeout, cleanup = self.func_table[strategy]
            print(f"using func {func}")

            pipe = await for_addr_infos(
                self.src,
                self.dest,
                func,
                timeout,
                cleanup,
                self,
                reply,
                conf,
            )

            # Strategy failed so continue.
            if pipe is None:
                continue

            # NOP -- don't process this result.
            if pipe == 1:
                await self.cleanup()
                return

            """
            # Ensure node protocol handler setup on pipe.
            if node_protocol not in pipe.msg_cbs:
                pipe.add_msg_cb(node_protocol)

            # Ensure ready set.
            # todo: get working for all
            self.node.pipe_ready(self.pipe_id, pipe)
            """

            await self.cleanup()
            return pipe

        await self.cleanup()
            
    async def direct_connect(self, af, pipe_id, src_info, dest_info, iface, addr_type, reply=None):
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
            msg_cb=self.node.msg_cb
        )

        if pipe is None:
            return

        await pipe.send(to_b(f"ID {pipe_id}"))
        self.node.pipe_ready(pipe_id, pipe)
        return pipe

    async def reverse_connect(self, af, pipe_id, src_info, dest_info, iface, addr_type, reply=None):
        print("in reverse connect")
        msg = ConMsg({
            "meta": {
                "af": af,
                "pipe_id": pipe_id,
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
        return await self.node.pipes[pipe_id]

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
    async def tcp_hole_punch(self, af, pipe_id, src_info, dest_info, iface, addr_type, reply=None):
        # Punch clients indexed by interface offset.
        if_index = src_info["if_index"]
        punch = self.node.tcp_punch_clients[if_index]
        stun_client = self.node.stun_clients[af][if_index]

        print(f"Punch pipe id = {pipe_id}")
        print(f'{self.dest["node_id"]}')
        print("trying tcp punch method")

        punch_mode, punch_state, punch_ret = await punch.proto_update(
            af,
            str(dest_info["ip"]),
            dest_info["nat"],
            self.dest["node_id"],
            pipe_id,
            stun_client,
            iface,
            same_machine=self.same_machine,
            reply=reply,
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
                pipe_id,
                self.dest["node_id"],
                2 if punch_state == TCP_PUNCH_IN_MAP else 0
            )
        )

        print("after schedule punch")
        msg = TCPPunchMsg({
            "meta": {
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
        return await self.node.pipes[pipe_id]

    # TODO improve this code?
    async def udp_turn_relay(self, af, pipe_id, src_info, dest_info, iface, addr_type, reply=None):
        if addr_type == NIC_BIND:
            return None

        print("in p2p pipe udp relay")
        peer_tup = relay_tup = None
        dest_peer = dest_relay = turn_client = None

        # Try TURN servers in random order.
        offsets = list(range(0, len(TURN_SERVERS)))
        random.shuffle(offsets)
        if reply is not None:
            offsets = [reply.payload.serv_id]
            dest_peer = reply.payload.peer_tup
            dest_relay = reply.payload.relay_tup

        print(self.node.turn_clients)
        print(pipe_id)

        # Attempt to connect to TURN server.
        for offset in offsets:
            try:
                # Attempt to load a TURN client.
                if pipe_id not in self.node.turn_clients:
                    print(f"{pipe_id} not in turn clients {self.node.turn_clients}")
                    peer_tup, relay_tup, turn_client = await get_turn_client(
                        af,
                        offset,
                        iface,
                        dest_peer=dest_peer,
                        dest_relay=dest_relay,
                        msg_cb=self.node.msg_cb,
                    )

                    # Load TURN client failed.
                    if turn_client is None:
                        continue

                    self.node.turn_clients[pipe_id] = turn_client
                else:
                    turn_client = self.node.turn_clients[pipe_id]

                if reply is not None:
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

                        self.node.pipe_ready(pipe_id, turn_client)

                        # Protocol end.
                        return 1
                    else:
                        self.node.pipe_ready(pipe_id, turn_client)

                # Return a new TURN request.
                msg = TURNMsg({
                    "meta": {
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
                        "peer_tup": peer_tup,
                        "relay_tup": relay_tup,
                        "serv_id": offset,
                    },
                })
                print(msg)
                self.msg_queue.put_nowait(msg)
                return await self.node.pipes[pipe_id]
            except:
                log_exception()
                continue

    def general_cleanup(self, pipe_id):
        del self.node.pipes[pipe_id]
        self.node.pipe_future(pipe_id)

    async def tcp_punch_cleanup(self, af, pipe_id, src_info, dest_info, iface, addr_type, reply=None):
        print("in tcp punch cleanup")
        #self.general_cleanup(pipe_id)
        node_id = self.dest["node_id"]
        if_index = src_info["if_index"]
        client = self.node.tcp_punch_clients[if_index]
        #await client.cleanup_state(node_id, pipe_id)
        print(client.state)
        print(self.msg_dispatcher_task)

    async def turn_cleanup(self, af, pipe_id, src_info, dest_info, iface, addr_type, reply=None):
        self.general_cleanup(pipe_id)
        if pipe_id not in self.node.turn_clients:
            return
        return
        
        turn_client = self.node.turn_clients[pipe_id]
        await turn_client.close()
        del self.node.turn_clients[pipe_id]


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