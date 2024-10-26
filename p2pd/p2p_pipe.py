import asyncio
from .address import Address
from .pipe_utils import pipe_open, PipeEvents
from .p2p_addr import *
from .tcp_punch_client import *
from .p2p_utils import for_addr_infos, get_turn_client
from .p2p_utils import get_first_working_turn_client
from .p2p_utils import CON_ID_MSG, f_path_txt
from .p2p_protocol import *
from .tcp_punch_client import *
from .turn_client import TURNClient

async def log_pipe(addr_type, func_txt, pipe):
    path_txt = f_path_txt(addr_type)
    if isinstance(pipe, TURNClient):
        remote_tup = list(pipe.peers.values())[0]
        local_tup = await pipe.relay_tup_future
    else:
        local_tup = pipe.sock.getsockname()[:2]
        remote_tup = pipe.sock.getpeername()[:2]
    msg = f"<{func_txt}> Established {path_txt} {local_tup} -> {remote_tup}"
    msg += f" on '{pipe.route.interface.name}'"
    return msg

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

        # Mapping for funcs over addr infos.
        # Loop over the most likely strategies left.
        # func, timeout, cleanup, same_if, max_pairs
        self.func_table = {
            # Short timeouts for direct TCP cons.
            P2P_DIRECT: [self.direct_connect, 2, None, 1, 6, "direct"],
            P2P_REVERSE: [self.reverse_connect, 4, None, 1, 6, "reverse"],

            # Large timeout for meetings with a state cleanup.
            # <20 timeout can cause timeouts for punching.
            P2P_PUNCH: [self.tcp_hole_punch, 20,
                        self.tcp_punch_cleanup, 0, 4, "punch"],

            # Large timeout, end refreshers, disable LAN cons.
            # <20 timeout can cause timeouts for relay setup.
            P2P_RELAY: [self.udp_turn_relay, 20, self.turn_cleanup, 1, 2, "relay"],
        }

    def route_msg(self, msg, reply=None, m=0):
        vk = None
        if reply is not None:
            vk = h_to_b(reply.cipher.vk)

        msg.cipher.vk = to_h(self.node.vk.to_string("compressed"))
        self.node.sig_msg_queue.put_nowait([msg, vk, m])

    async def connect(self, strategies=P2P_STRATEGIES, reply=None, conf=P2P_PIPE_CONF):
        # Try strategies to achieve a connection.
        pipe = None
        for strategy in strategies:
            # Skip invalid strategy.
            if strategy not in self.func_table:
                continue

            # Returns a pipe given comp addr info pairs.
            func, timeout, cleanup, has_set_bind, max_pairs, func_txt = \
                self.func_table[strategy]
            pipe, addr_type = await async_wrap_errors(
                for_addr_infos(
                    func_txt,
                    func,
                    timeout,
                    cleanup,
                    has_set_bind,
                    max_pairs,
                    reply,
                    self,
                    conf,
                )
            )

            # Check return value.
            if not isinstance(pipe, PipeEvents):
                continue

            # Indicate success result (long.)
            msg = await log_pipe(addr_type, func_txt, pipe)
            Log.log_p2p(msg, self.node.node_id[:8])
            pipe.subscribe(SUB_ALL)
            return pipe
            
    async def direct_connect(self, af, pipe_id, src_info, dest_info, iface, addr_type, reply=None):
        # Connect to this address.
        dest = (
            str(dest_info["ip"]),
            dest_info["port"],
        )

        # (1) Get first interface for AF.
        # (2) Build a 'route' from it with it's main NIC IP.
        # (3) Bind to the route at port 0. Return itself.
        if af == IP4:
            route = await iface.route(af).bind()
        if af == IP6:
            if "fe80" == dest[0][:4]:
                route = iface.route(af)
                await route.bind(
                    ips=str(route.link_locals[0])
                )
            else:
                route = await iface.route(af).bind()

        # Connect to destination.
        pipe = await pipe_open(
            route=route,
            proto=TCP,
            dest=dest,
            msg_cb=self.node.msg_cb
        )

        if pipe is None:
            return
        
        if pipe.sock is None:
            return

        await pipe.send(CON_ID_MSG + to_b(f" {pipe_id}"))
        self.node.pipe_ready(pipe_id, pipe)
        return pipe

    async def reverse_connect(self, af, pipe_id, src_info, dest_info, iface, addr_type, reply=None):
        msg = ConMsg({
            "meta": {
                "ttl": int(self.node.sys_clock.time()) + 10,
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

        self.route_msg(msg, m=1)
        return await self.node.pipes[pipe_id]

    async def tcp_hole_punch(self, af, pipe_id, src_info, dest_info, nic, addr_type, reply=None):
        # Load TCP punch client for this pipe ID.
        if pipe_id in self.node.tcp_punch_clients:
            puncher = self.node.tcp_punch_clients[pipe_id]
            assert(src_info == puncher.src_info)
            if dest_info != puncher.dest_info:
                """
                If an address fetch gets an old address a node replies
                with its current address info in a reply which
                is passed back to this function.
                """
                self.node.log("p2p", f"<punch> Updating dest info {dest_info}")
                puncher.dest_info = dest_info
        else:
            # Create a new puncher for this pipe ID.
            if_index = src_info["if_index"]
            stuns = self.node.stun_clients[af][if_index]

            # Skip if no STUN clients loaded.
            if not len(stuns):
                return None
            
            # Create a new puncher for this pipe ID.
            puncher = TCPPuncher(
                af,
                src_info,
                dest_info,
                stuns,
                self.node.sys_clock,
                nic,
                self.same_machine,
            )

            # Save a reference to node.
            puncher.set_parent(pipe_id, self.node)

            # Setup process manager and executor.
            # So that objects are shareable over processes.
            puncher.setup_multiproc(self.node.pp_executor)

            # Save puncher reference.
            self.node.tcp_punch_clients[pipe_id] = puncher

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
        self.node.active_punchers = min(
            self.node.max_punchers,
            self.node.active_punchers + 1
        )

        """
        Punching is delayed for a few seconds to
        ensure there's enough time to receive any
        updated mappings for the dest peer (if any.)
        """
        task = create_task(
            self.node.schedule_punching_with_delay(
                pipe_id,
                n=2 if puncher.side == INITIATOR else 0
            )
        )
        self.node.tasks.append(task)

        # Forward protocol details to peer.
        mappings = [m.toJSON() for m in ret[0]]
        msg = TCPPunchMsg({
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
                "punch_mode": puncher.punch_mode,
                "ntp": ret[1],
                "mappings": mappings,
            },
        })

        self.route_msg(msg, reply=reply, m=2)

        # Prevent protocol loop.
        pipe = await self.node.pipes[pipe_id]

        # Watch this pipe for idleness.
        self.node.last_recv_table[pipe.sock] = time.time()
        self.node.last_recv_queue.append(pipe)

        # Close pipe if ping times out.
        return pipe

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
                m = f"Whitelist {dest_peer} -> {our_relay} to"
                m += f" '{iface.name}'"
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

        try:
            self.route_msg(msg, reply=reply, m=3)
            return await self.node.pipes[pipe_id]
        except:
            log_exception()

    async def tcp_punch_cleanup(self, af, pipe_id, src_info, dest_info, nic, addr_type, reply=None):
        self.node.active_punchers = max(
            0,
            self.node.active_punchers - 1
        )

    async def turn_cleanup(self, af, pipe_id, src_info, dest_info, iface, addr_type, reply=None):
        if pipe_id not in self.node.turn_clients:
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