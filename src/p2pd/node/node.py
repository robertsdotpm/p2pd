"""
Note:
Reusing address can hide socket errors and
make servers appear broken when they're not.
"""

from typing import Any, Callable, List, Optional
from aionetiface import (
    Daemon, dict_child, NET_CONF, log_exception,
    Pipe, PipeClient, TCPClientProtocol, PipeEvents,
    get_aionetiface_install_root,
)
from .node_defs import NODE_PORT, NODE_CONF
from .node_utils import resolve_install_path, make_stop_pair, norm_listen_ips, pipe_future, pipe_ready
from .node_start import node_start
from .node_stop import node_stop
from .node_protocol import node_protocol
from .node_connect import apply_listen_ips, connect as node_connect
from .node_resources import NodeResources

# Alias kept so that older callers (e.g. traversal_manager, namebump tests)
# that import get_p2pd_install_root from this module continue to work.
get_p2pd_install_root = get_aionetiface_install_root


# Main class for the P2P node server.
class Node(Daemon):
    """Core P2P node server managing connections, traversal, and signaling."""

    def __init__(
        self,
        ifs: Optional[List[Any]] = None,
        ip: Optional[Any] = None,
        port: int = NODE_PORT,
        stop_rw: Optional[Any] = None,
        conf: Optional[Any] = None,
    ) -> None:
        if conf is None:
            conf = NODE_CONF
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

    async def msg_cb(self, msg: Any, client_tup: Any, pipe: Any) -> None:
        """Route inbound pipe messages through the node protocol dispatcher."""
        await node_protocol(self, msg, client_tup, pipe)

    def up_cb(self, _data: Any, _client_tup: Any, pipe: Any) -> None:
        """Register every newly-accepted inbound TCP pipe by its remote tuple.

        Called by aionetiface's PipeEvents.connection_made before any data
        arrives. The TraversalManager keeps a tup -> pipe map so a later
        ConIdMsg over the signal channel can rendezvous the data pipe with
        the plugin_id the reverse_connect plugin is awaiting on -- without
        needing an in-band first-message handshake on every inbound.
        """
        if self.traversal is None:
            return
        self.traversal.register_inbound_pipe(pipe)

    async def start(self, sys_clock: Optional[Any] = None, out: bool = False, cout: Callable = print) -> "Node":
        """Run the full node startup sequence and return self when the node is ready."""
        await node_start(self, sys_clock=sys_clock, out=out, cout=cout)
        return self

    async def connect(self, af: Any, route_type: Any, pnp_addr: Any, plugin_name: Optional[str] = None) -> Any:
        """Establish a P2P connection to pnp_addr using the given AF, route type, and optional plugin."""
        return await node_connect(self, af, route_type, pnp_addr, plugin_name)

    async def nickname(self, name: Any, value: Optional[Any] = None) -> str:
        """Register name in the PNP system, defaulting value to this node's address bytes."""
        value = value or self.addr_bytes
        name = await self.nick_client.put(name, value)
        return name

    def address(self) -> Optional[bytes]:
        """Return the node's address bytes, or None if the node has not started."""
        return self.addr_bytes

    def supported(self) -> List[Any]:
        """Return sorted list of address families supported across all interfaces."""
        afs = set()
        for nic in self.ifs:
            for af in nic.supported():
                afs.add(af)

        return sorted(tuple(afs))

    def add_msg_cb(self, msg_cb: Callable) -> None:
        """Register a message callback to receive all inbound pipe messages."""
        self.msg_cbs.append(msg_cb)

    def on_plugin_done(self, future: Any) -> None:
        """Attach the node message callback to any pipe-like result from a finished plugin."""
        try:
            result = future.result()
            pipe_like = (Pipe, PipeClient, TCPClientProtocol, PipeEvents)
            if isinstance(result, pipe_like):
                result.add_msg_cb(self.msg_cb)
        except BaseException:
            log_exception()

    def pipe_future(self, pipe_id: str) -> Any:
        """Return a Future that resolves when the inbound pipe with pipe_id is ready."""
        return pipe_future(self.inbound_pipes, pipe_id)

    def pipe_ready(self, pipe_id: str, pipe: Any) -> Any:
        """Resolve the Future for pipe_id with the given pipe, unblocking any waiters."""
        return pipe_ready(self.inbound_pipes, pipe_id, pipe)

    async def close(self) -> None:
        """Gracefully shut down the node, closing all connections, tasks, and services."""
        await node_stop(self)

    def __await__(self) -> Any:
        return self.start().__await__()

    async def __aenter__(self) -> "Node":
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> bool:
        await self.close()
        return False
