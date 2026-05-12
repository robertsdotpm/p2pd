"""
Note:
Reusing address can hide socket errors and
make servers appear broken when they're not.
"""
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
        ifs=None,
        ip=None,
        port=NODE_PORT,
        stop_rw=None,
        conf=None,
        node_name=None,
    ):
        if conf is None:
            conf = NODE_CONF
        super().__init__()
        self.conf = dict_child(conf, NET_CONF)
        self.install_path = resolve_install_path(self.conf)
        self.stop_reader, self.stop_writer = make_stop_pair(stop_rw)

        # Stable on-disk identity tag. node_name selects which signing-key
        # file is loaded ("PRIV_KEY_DONT_SHARE_v3_<name>.hex"); None falls
        # back to a single shared "default" file at install_path. Two nodes
        # sharing a node_name share a private key -- intentional, but the
        # caller is responsible for not booting two such nodes on one box.
        self.node_name = node_name

        # network identity.
        self.ifs = ifs if ifs is not None else []
        self.listen_ips = norm_listen_ips(ip if ip is not None else [])
        self.listen_port = port
        if self.listen_ips:
            apply_listen_ips(self)

        # Resource state. msg_cbs is a set so add_msg_cb is idempotent --
        # callers (and on_plugin_done after a plugin pre-populates an
        # internal pipe) can register the same callback multiple times
        # without it firing twice per inbound msg.
        self.msg_cbs = set()
        self.inbound_pipes = {}
        self.resources = NodeResources()

        # Set on start() — not available until node is running.
        self.traversal = None
        self.router = None
        self.addr_bytes = None  # serialized
        self.addr_map = None  # parsed dict

        # Optional TelemetryWriter; set by caller after Node() to opt in.
        self.telemetry = None

    async def msg_cb(self, msg, client_tup, pipe):
        """Route inbound pipe messages through the node protocol dispatcher."""
        await node_protocol(self, msg, client_tup, pipe)

    def up_cb(self, _data, _client_tup, pipe):
        """Notify on every newly-accepted inbound TCP pipe.

        Rendezvous is in-band now: the initiator writes a
        b"P2P-CID:<plugin_id>\\n" frame as the first bytes on the new TCP
        pipe and node_protocol peels it off on first inbound message.
        Nothing to do here beyond observability -- the daemon already
        wires self.msg_cb to the pipe so node_protocol receives the
        frame as part of normal data flow.
        """

    async def start(self, sys_clock=None, out=False, cout=print):
        """Run the full node startup sequence and return self when the node is ready."""
        await node_start(self, sys_clock=sys_clock, out=out, cout=cout)
        return self

    async def connect(self, af, route_type, pnp_addr, plugin_name=None):
        """Establish a P2P connection to pnp_addr using the given AF, route type, and optional plugin."""
        return await node_connect(self, af, route_type, pnp_addr, plugin_name)

    async def nickname(self, name, value=None):
        """Register name in the PNP system, defaulting value to this node's address bytes."""
        value = value or self.addr_bytes
        return await self.nick_client.put(name, value)

    def address(self):
        """Return the node's address bytes, or None if the node has not started."""
        return self.addr_bytes

    def supported(self):
        """Return sorted list of address families supported across all interfaces."""
        afs = set()
        for nic in self.ifs:
            for af in nic.supported():
                afs.add(af)

        return sorted(tuple(afs))

    def add_msg_cb(self, msg_cb):
        """Register a message callback to receive all inbound pipe messages (idempotent)."""
        self.msg_cbs.add(msg_cb)

    def on_plugin_done(self, future):
        """Attach the node message callback to any pipe-like result from a finished plugin.

        Idempotent at every layer: result.add_msg_cb backs onto a set,
        so a plugin that pre-populates its internal pipe (tcp_punch's
        reverse_server, in practice) can call add here too without
        producing a double-dispatch.
        """
        try:
            result = future.result()
            pipe_like = (Pipe, PipeClient, TCPClientProtocol, PipeEvents)
            if isinstance(result, pipe_like):
                result.add_msg_cb(self.msg_cb)
        except BaseException:
            log_exception()

    def pipe_future(self, pipe_id):
        """Return a Future that resolves when the inbound pipe with pipe_id is ready."""
        return pipe_future(self.inbound_pipes, pipe_id)

    def pipe_ready(self, pipe_id, pipe):
        """Resolve the Future for pipe_id with the given pipe, unblocking any waiters."""
        return pipe_ready(self.inbound_pipes, pipe_id, pipe)

    async def close(self):
        """Gracefully shut down the node, closing all connections, tasks, and services."""
        await node_stop(self)

    def __await__(self):
        return self.start().__await__()

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *_):
        await self.close()
        return False
