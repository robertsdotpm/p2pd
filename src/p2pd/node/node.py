"""
Note:
Reusing address can hide socket errors and
make servers appear broken when they're not.
"""

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
    """Core P2P node server managing connections, traversal, and signaling."""

    def __init__(self, ifs=None, ip=None, port=NODE_PORT, stop_rw=None, conf=NODE_CONF):
        # type: (Optional[List[Any]], Optional[Any], int, Optional[Any], Any) -> None
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
        self.addr_map = None  # parsed dict

    async def msg_cb(self, msg, client_tup, pipe):
        # type: (Any, Any, Any) -> None
        await node_protocol(self, msg, client_tup, pipe)

    async def start(self, sys_clock=None, out=False, cout=print):
        # type: (Optional[Any], bool, Callable) -> Node
        await node_start(self, sys_clock=sys_clock, out=out, cout=cout)
        return self

    async def connect(self, af, route_type, pnp_addr, plugin_name=None):
        # type: (Any, Any, Any, Optional[str]) -> Any
        return await node_connect(self, af, route_type, pnp_addr, plugin_name)

    async def nickname(self, name, value=None):
        # type: (Any, Optional[Any]) -> str
        value = value or self.addr_bytes
        name = await self.nick_client.put(name, value)
        return name

    def address(self):
        # type: () -> Optional[bytes]
        return self.addr_bytes

    def supported(self):
        # type: () -> List[Any]
        afs = set()
        for nic in self.ifs:
            for af in nic.supported():
                afs.add(af)

        return sorted(tuple(afs))

    def add_msg_cb(self, msg_cb):
        # type: (Callable) -> None
        self.msg_cbs.append(msg_cb)

    def on_plugin_done(self, future):
        # type: (Any) -> None
        try:
            result = future.result()
            pipe_like = (Pipe, PipeClient, TCPClientProtocol, PipeEvents)
            if isinstance(result, pipe_like):
                result.add_msg_cb(self.msg_cb)
        except BaseException:
            log_exception()

    def pipe_future(self, pipe_id):
        # type: (str) -> Any
        return pipe_future(self.inbound_pipes, pipe_id)

    def pipe_ready(self, pipe_id, pipe):
        # type: (str, Any) -> Any
        return pipe_ready(self.inbound_pipes, pipe_id, pipe)

    async def close(self):
        # type: () -> None
        await node_stop(self)

    def __await__(self):
        # type: () -> Any
        return self.start().__await__()

    async def __aenter__(self):
        # type: () -> Node
        await self.start()
        return self

    async def __aexit__(self, *_):
        # type: (*Any) -> bool
        await self.close()
        return False
