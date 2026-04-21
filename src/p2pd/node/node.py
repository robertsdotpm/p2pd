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
    def __init__(self, ifs=None, ip=None, port=NODE_PORT, stop_rw=None, conf=NODE_CONF):
        super().__init__()
        self.conf = dict_child(conf, NET_CONF)
        self.install_path = resolve_install_path(self.conf)
        self.stop_reader, self.stop_writer = make_stop_pair(stop_rw)

        # network identity.
        self.ifs = ifs if ifs is not None else []
        self.listen_ips = norm_listen_ips(ip if ip is not None else [])
        self.listen_port = port
        if self.listen_ips:
            apply_listen_ips(self)

        # Resource state.
        self.msg_cbs = []
        self.inbound_pipes = {}
        self.resources = NodeResources()

        # Set on start() — not available until node is running.
        self.traversal = None
        self.router = None
        self.addr_bytes = None  # serialized
        self.addr_map = None    # parsed dict

    async def msg_cb(self, msg, client_tup, pipe):
        await node_protocol(self, msg, client_tup, pipe)

    async def start(self, sys_clock=None, out=False, cout=print):
        await node_start(self, sys_clock=sys_clock, out=out, cout=cout)
        return self

    async def connect(self, af, route_type, pnp_addr, plugin_name=None):
        return await node_connect(self, af, route_type, pnp_addr, plugin_name)

    async def nickname(self, name, value=None):
        value = value or self.addr_bytes
        name = await self.nick_client.put(name, value)
        return name

    def address(self):
        return self.addr_bytes

    def supported(self):
        afs = set()
        for nic in self.ifs:
            for af in nic.supported():
                afs.add(af)
                
        return sorted(tuple(afs))
    
    def add_msg_cb(self, msg_cb):
        self.msg_cbs.append(msg_cb)

    def on_plugin_done(self, future):
        try:
            result = future.result()
            pipe_like = (Pipe, PipeClient, TCPClientProtocol, PipeEvents)
            if isinstance(result, pipe_like):
                result.add_msg_cb(self.msg_cb)
        except Exception:
            log_exception()

    def pipe_future(self, pipe_id):
        return pipe_future(self.inbound_pipes, pipe_id)

    def pipe_ready(self, pipe_id, pipe):
        return pipe_ready(self.inbound_pipes, pipe_id, pipe)
    
    async def close(self):
        await node_stop(self)

    def __await__(self):
        return self.start().__await__()

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *_):
        await self.close()
        return False
