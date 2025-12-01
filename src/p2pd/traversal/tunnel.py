import asyncio
from collections import OrderedDict
from ..net.pipe.pipe_events import PipeEvents
from ..node.node_addr import *
from ..protocol.turn.turn_client import TURNClient
from .traversal_utils import *
from ..node.node_protocol import *
from .plugins.direct_connect.main import direct_connect
from .plugins.punch.punch_protocol import PunchProtocol
from .plugins.turn.main import udp_turn_relay, turn_cleanup
from .plugins.reverse_connect.main import reverse_connect
from ..node.nickname import *
from .traversal_address import *

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
class Tunnel():
    def __init__(self, dest_bytes, node):
        # Record main references.
        self.node = node

        # Parse address bytes to dicts.
        self.dest_bytes = dest_bytes
        self.dest = parse_node_addr(dest_bytes)
        self.src  = self.node.p2p_addr
        self.src_bytes = self.node.addr_bytes
        
        # Is this a connection to a node on the same machine?
        if self.dest["machine_id"] == self.src["machine_id"]:
            self.same_machine = True
        else:
            self.same_machine = False

        # Encapsulate stun proto details.
        self.punch_proto = PunchProtocol(
            self.node.stun_clients,
            self.node.sys_clock,
            self.node.pp_executor
        )

        # Mapping for funcs over addr infos.
        # Loop over the most likely strategies left.
        # func, timeout, cleanup, same_if, max_pairs
        self.func_table = {
            # Short timeouts for direct TCP cons.
            P2P_DIRECT: [direct_connect, 2, None, 1, 6, "direct"],
            P2P_REVERSE: [reverse_connect, 4, None, 1, 6, "reverse"],

            # Large timeout for meetings with a state cleanup.
            # <20 timeout can cause timeouts for punching.
            # todo: add cleanup back in
            P2P_PUNCH: [self.punch_proto.protocol, 20, None, 0, 4, "punch"],

            # Large timeout, end refreshers, disable LAN cons.
            # <20 timeout can cause timeouts for relay setup.
            P2P_RELAY: [udp_turn_relay, 20, turn_cleanup, 1, 2, "relay"],
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
            
            """
            has set bind? == same if?
                select_dest_ipr(
                    af,
                    pp.same_machine,
                    src_info,
                    dest_info,
                    [use_addr_type],

                    # can you make this case
                    # run for all
                    # try it
                    has_set_bind,
                )

                some methods need to bind on set src ports. 
                If a method is meant to be used to connect to machines
                on the same interface, then it will conflict with
                binding on a set port.
            """
            

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
            log_p2p(msg, self.node.node_id[:8])
            pipe.subscribe(SUB_ALL)
            return pipe
        
# Connect to a remote P2P node using a number of techniques.
async def connect_tunnel(node, pnp_addr, strategies=P2P_STRATEGIES, conf=P2P_PIPE_CONF):
    # Get most recent address bytes if given a nickname.
    if pnp_name_has_tld(pnp_addr):
        addr_bytes = await get_updated_addr_bytes(node, pnp_addr)
    else:
        addr_bytes = pnp_addr

    msg = fstr("Connecting to '{0}'", (addr_bytes,))
    log_p2p(msg, node.node_id[:8])
    tunnel = Tunnel(addr_bytes, node)
    for af in conf["addr_families"]:
        af_conf = copy.deepcopy(conf)
        af_conf["addr_families"] = [af]
        pipe = await tunnel.connect(strategies, reply=None, conf=af_conf)
        if pipe is not None:
            return pipe
        
    return pipe

