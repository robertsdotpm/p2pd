"""
Note:
Reusing address can hide socket errors and
make servers appear broken when they're not.
"""
import asyncio
from ..net.daemon import *
from .node_addr import *
from .node_utils import *
from .nickname import *
from .node_start import *
from .node_stop import *
from ..utility.machine_id import *
from ..traversal.tunnel_address import *
from ..traversal.tunnel import *
from ..traversal.signaling.signaling_protocol import *

NODE_CONF = dict_child({
    "reuse_addr": False,
    "enable_upnp": True,
    "sig_pipe_no": SIGNAL_PIPE_NO,
}, NET_CONF)

# Main class for the P2P node server.
class P2PNode(Daemon):
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
        self.sig_msg_queue_worker_task = None

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
    
    async def close(self):
        await node_stop(self)
    
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

    def log(self, t, m):
        node_id = self.node_id[:8]
        msg = fstr("{0}: <{1}> {2}", (t, node_id, m,))
        log(msg)

    # Return supported AFs based on all NICs for the node.
    def supported(self):
        afs = set()
        for nic in self.ifs:
            for af in nic.supported():
                afs.add(af)

        # Make IP4 earliest in the list.
        return sorted(tuple(afs))

    async def listen_on_ifs(self):
        # Multi-iface connection facilitation.
        for nic in self.ifs:
            # Listen on first route for AFs.
            outs = await self.listen_local(
                TCP,
                self.listen_port,
                nic
            )

            # Add global address listener.
            if IP6 in nic.supported():
                route = await nic.route(IP6).bind(
                    port=self.listen_port
                )

                out = await self.add_listener(TCP, route)
                outs.append(out)

    def pipe_future(self, pipe_id):
        if pipe_id not in self.pipes:
            self.pipes[pipe_id] = asyncio.Future()

        return pipe_id

    def pipe_ready(self, pipe_id, pipe):
        if pipe_id not in self.pipes:
            log(fstr("pipe ready for non existing pipe {0}!", (pipe_id,)))
            return
        
        if not self.pipes[pipe_id].done():
            self.pipes[pipe_id].set_result(pipe)
        
        return pipe

    async def load_machine_id(self, app_id, netifaces):
        # Set machine id.
        try:
            return hashed_machine_id(app_id)
        except:
            return await fallback_machine_id(
                netifaces,
                app_id
            )

    # Accomplishes port forwarding and pin hole rules.
    async def forward(self, port):
        async def forward_server(server):
            ret = await server.route.forward(port=port)
            msg = fstr("<upnp> Forwarded {0}:{1}", (server.route.ext(), port,))
            msg += fstr(" on {0}", (server.route.interface.name,))
            if ret:
                Log.log_p2p(msg, self.node_id[:8])

        # Loop over all listen pipes for this node.
        await self.for_server_in_self(forward_server)

