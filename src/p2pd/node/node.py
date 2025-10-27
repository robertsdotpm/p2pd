"""
Note:
Reusing address can hide socket errors and
make servers appear broken when they're not.
"""
import asyncio
from ..net.daemon import *
from .node_addr import *
from .node_utils import *
from .node_extra import *
from .nickname import *
from .node_start import *
from ..traversal.tunnel_address import *
from ..traversal.tunnel import *
from ..traversal.signaling.signaling_protocol import *

NODE_CONF = dict_child({
    "reuse_addr": False,
    "enable_upnp": True,
    "sig_pipe_no": SIGNAL_PIPE_NO,
}, NET_CONF)

# Main class for the P2P node server.
class P2PNode(P2PNodeExtra, Daemon):
    def __init__(self, ifs=[], port=3000, conf=NODE_CONF):
        super().__init__()
        self.__name__ = "P2PNode"
        
        # Main variables for the class.
        self.conf = conf
        self.listen_port = port
        self.ifs = ifs

        # Handlers for the node protocol.
        self.msg_cbs = []

        # Main pipe connections.
        self.pipes = {} # by pipe_id
        self.tcp_punch_clients = {} # by if_index
        self.turn_clients = {} # by pipe_id
        self.signal_pipes = {} # by MQTT_SERVERS index

        # Pending TCP punch queue.
        self.punch_queue = asyncio.Queue()
        self.punch_worker_task = None
        self.active_punchers = 0
        self.max_punchers = 0

        # Signal protocol class instance.
        self.sig_proto_handlers = SigProtoHandlers(self)
        self.sig_msg_queue = asyncio.Queue()
        self.sig_msg_dispatcher_task = None

        # Fixed reference for long-running tasks.
        self.tasks = []

        # Watch for idle connections.
        self.last_recv_table = {} # [pipe] -> time
        self.last_recv_queue = [] # FIFO pipe ref

        # Set on start.
        self.addr_bytes = None
        self.addr_futures = {}

    def add_msg_cb(self, msg_cb):
        self.msg_cbs.append(msg_cb)

    # Used by the node servers.
    async def msg_cb(self, msg, client_tup, pipe):
        """
        TCP is stream-orientated and may buffer small sends.
        New lines end messages. So multiple messages can
        be read by splitting at a new line. Excluding
        complex cases of partial replies (who cares for now.)

        TODO: implement actual buffered protocol.
        """

        # Recv a message for a pipe being monitored for idleness.
        if pipe in self.last_recv_queue:
            self.last_recv_table[pipe.sock] = time.time()

        msgs = msg.split(b"\n")
        for msg in msgs:
            # Pass messages directly to clients own handlers.
            # Don't interfere so they can write their own protocol.
            await node_protocol(self, msg, client_tup, pipe)
            for msg_cb in self.msg_cbs:
                run_handler(pipe, msg_cb, client_tup, msg)

    async def start(self, sys_clock=None, out=False):
        await node_start(self, sys_clock=sys_clock, out=out)
        return self
    
    def __await__(self):
        return self.start().__await__()
    
    # Connect to a remote P2P node using a number of techniques.
    async def connect(self, pnp_addr, strategies=P2P_STRATEGIES, conf=P2P_PIPE_CONF):
        return await connect_tunnel(self, pnp_addr, strategies, conf)

    # Get our node server's address.
    def address(self):
        return self.addr_bytes
    
    # Simple KVS over a few servers.
    # Returns your nickname + a tld designating server.
    async def nickname(self, name, value=None):
        value = value or self.address()
        name = await self.nick_client.push(
            name,
            value
        )

        msg = fstr("Setting nickname '{0}' = '{1}'", (name, value,))
        #Log.log_p2p(msg, self.node_id[:8])
        return name

