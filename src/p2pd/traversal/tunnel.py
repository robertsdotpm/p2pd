import asyncio
from ..net.pipe.pipe_utils import PipeEvents
from ..node.node_addr import *
from .plugins.tcp_punch.tcp_punch_client import *
from ..protocol.turn.turn_client import TURNClient
from ..node.node_utils import for_addr_infos
from ..node.node_utils import f_path_txt
from ..node.node_protocol import *
from .plugins.direct_connect.main import direct_connect
from .plugins.tcp_punch.main import tcp_hole_punch, tcp_punch_cleanup
from .plugins.turn.main import udp_turn_relay, turn_cleanup
from .plugins.reverse_connect.main import reverse_connect

async def log_pipe(addr_type, func_txt, pipe):
    path_txt = f_path_txt(addr_type)
    if isinstance(pipe, TURNClient):
        remote_tup = list(pipe.peers.values())[0]
        local_tup = await pipe.relay_tup_future
    else:
        local_tup = pipe.sock.getsockname()[:2]
        remote_tup = pipe.sock.getpeername()[:2]
    msg = fstr("<{0}> Established {1} {2} -> {3}", (func_txt, path_txt, local_tup, remote_tup,))
    msg += fstr(" on '{0}'", (pipe.route.interface.name,))
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
            P2P_DIRECT: [direct_connect, 2, None, 1, 6, "direct"],
            P2P_REVERSE: [reverse_connect, 4, None, 1, 6, "reverse"],

            # Large timeout for meetings with a state cleanup.
            # <20 timeout can cause timeouts for punching.
            P2P_PUNCH: [tcp_hole_punch, 20,
                        tcp_punch_cleanup, 0, 4, "punch"],

            # Large timeout, end refreshers, disable LAN cons.
            # <20 timeout can cause timeouts for relay setup.
            P2P_RELAY: [udp_turn_relay, 20, self.turn_cleanup, 1, 2, "relay"],
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