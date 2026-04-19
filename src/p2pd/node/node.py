"""
Note:
Reusing address can hide socket errors and
make servers appear broken when they're not.
"""
import asyncio
from aionetiface import *
from .node_defs import *
from .node_utils import *
from .nickname import *
from .node_start import *
from .node_stop import *
from .node_protocol import node_protocol
from .node_connect import apply_listen_ips, connect as node_connect
from .node_resources import NodeResources
from ..traversal.traversal_address import *
from ..vendor.machine_id import *

# Alias kept so that older callers (e.g. traversal_manager, namebump tests)
# that import get_p2pd_install_root from this module continue to work.
get_p2pd_install_root = get_aionetiface_install_root

# Main class for the P2P node server.
class Node(Daemon):
    def __init__(self, ifs=[], ip=[], port=NODE_PORT, stop_rw=None, conf=NODE_CONF):
        super().__init__()
        self.__name__ = "Node"
        self.conf = dict_child(conf, NET_CONF)
        self.install_path = self.conf["install_path"] or get_aionetiface_install_root()

        # network identity.
        self.ifs = ifs
        self.listen_ips = norm_listen_ips(ip)
        self.listen_port = port
        if self.listen_ips:
            apply_listen_ips(self)

        # Stop signal socket pair for cross-process shutdown.
        if not stop_rw:
            stop_rw = make_stop_pair()
        self.stop_reader, self.stop_writer = stop_rw

        # Protocol state.
        self.msg_cbs = []
        self.inbound_pipes = {}

        # Resource manager — owns tasks, factories, idle tracking.
        self.resources = NodeResources()

        # Set on start() — not available until node is running.
        self.traversal = None
        self.router = None
        self.addr_bytes = None

    def on_traversal_done(self, future):
        try:
            result = future.result()
            pipe_like = (Pipe, PipeClient, TCPClientProtocol, PipeEvents)
            if isinstance(result, pipe_like):
                result.add_msg_cb(self.msg_cb)
        except Exception:
            log_exception()

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
        if pipe in self.resources.last_recv_queue:
            self.resources.last_recv_table[pipe.sock] = time.time()

        # Run msg_cbs across messages.
        msgs = msg.split(b"\n")
        coros = []
        for msg in msgs:
            # node_protocol returns a coroutine
            coros.append(node_protocol(self, msg, client_tup, pipe))

            # wrap msg_cbs as coroutines
            for msg_cb in self.msg_cbs:
                coros.append(msg_cb(msg, client_tup, pipe))

        # Run all coroutines concurrently, collect exceptions instead of propagating
        results = await asyncio.gather(*coros, return_exceptions=True)

        # Handle exceptions.
        for r in results:
            if isinstance(r, KeyboardInterrupt):
                log("reraising key interrupt")
                raise r
            elif isinstance(r, Exception):
                log("msg_cb coro raised: " + repr(r))

    async def start(self, sys_clock=None, out=False, cout=print):
        await node_start(self, sys_clock=sys_clock, out=out, cout=cout)
        return self

    async def close(self):
        await node_stop(self)

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *_):
        await self.close()
        return False

    def __await__(self):
        return self.start().__await__()
    
    async def connect(self, af, route_type, pnp_addr, plugin_name=None):
        return await node_connect(self, af, route_type, pnp_addr, plugin_name)

    # Get our node server's address.
    def address(self):
        return self.addr_bytes
    
    # Simple KVS over a few servers.
    # Returns your nickname + a tld designating server.
    async def nickname(self, name, value=None):
        value = value or self.address()
        name = await self.nick_client.put(
            name,
            value
        )

        msg = fstr("Setting nickname '{0}' = '{1}'", (name, value,))
        #log_p2p(msg, self.node_id[:8])
        return name

    # Return supported AFs based on all NICs for the node.
    def supported(self):
        afs = set()
        for nic in self.ifs:
            for af in nic.supported():
                afs.add(af)

        # Make IP4 earliest in the list.
        return sorted(tuple(afs))

    def pipe_future(self, pipe_id):
        return pipe_future(self.inbound_pipes, pipe_id)

    def pipe_ready(self, pipe_id, pipe):
        return pipe_ready(self.inbound_pipes, pipe_id, pipe)

