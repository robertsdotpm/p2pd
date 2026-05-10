"""Base class and lifecycle helpers for traversal plugins."""
import asyncio
from aionetiface import to_s, rand_plain, log, NIC_BIND, EXT_BIND, LOOPBACK_BIND


class Plugin:
    """Abstract base class for P2P connection traversal strategy plugins."""

    # Route types this plugin will accept combos for. auto_combos /
    # auto_combo_batches consult this to skip combos a plugin would
    # just no-op on. Default: every route_type is fair game; plugins
    # override the tuple to opt out of specific paths.
    route_types = (NIC_BIND, LOOPBACK_BIND, EXT_BIND)

    def __init__(self):
        self.result = asyncio.Future()
        self.plugin_id = to_s(rand_plain(15))
        self.has_reply = asyncio.Event()
        self.sig_pipe = None
        self.src_map = None
        self.dest_map = None
        self.af = None
        self.src = None
        self.dest = None
        self.nic = None
        self.route_type = None
        self.same_machine = None
        self.set_bind = None
        self.timeout = None
        self.inbound_pipes = None
        # Back-reference to the TraversalManager that owns this plugin.
        # Set by manager.create_plugin so meta-plugins (fan_out) can
        # spawn and run children. Regular plugins ignore it.
        self.manager = None
        self.signal_sender = None

    def set_addrs(self, src_map, dest_map):
        """Store the source and destination full address maps for this plugin."""
        self.src_map = src_map
        self.dest_map = dest_map

    def set_routing(self, af, src, dest, nic):
        """Configure the address family, interface info, and NIC to use for this traversal."""
        self.af = af
        self.src = src
        self.dest = dest
        self.nic = nic

    async def bind(self, port=0):
        """Return a route bound to this plugin's resolved src IP."""
        return await self.nic.route(self.af).bind(ips=self.src["ip"], port=port)

    def set_context(self, route_type, same_machine, set_bind, timeout):
        """Set the route type, same-machine flag, bind preference, and timeout for this plugin.

        Routing-decision (dest ip / port selection) lives in
        traversal_manager.create_plugin -> resolve_pair, which runs
        before set_context. By the time this fires, src["ip"] /
        dest["ip"] / dest["port"] are already the resolved values.
        """
        self.route_type = route_type
        self.same_machine = same_machine
        self.set_bind = set_bind
        self.timeout = timeout

    def set_inbound_pipes(self, pipes, plugin_id=None):
        """Attach the shared inbound-pipe dict and optionally override the plugin_id."""
        self.plugin_id = plugin_id or self.plugin_id
        self.inbound_pipes = pipes

    def set_send_signal(self, send_signal):
        """Register the manager-level function plugins call to send signal messages."""
        self.signal_sender = send_signal

    async def send_signal(self, msg, relay_no=2):
        """Delegate sending a signal message to the manager, passing self as the plugin context."""
        return await self.signal_sender(msg, self, relay_no)

    def register_inbound(self):
        """Pre-register a Future in inbound_pipes so arriving connections are not missed."""
        # Register before sending any signal to avoid a race where the inbound
        # connection arrives before the future exists.
        self.inbound_pipes[self.plugin_id] = asyncio.Future()

    async def wait_for_inbound(self):
        """Await the Future for this plugin's inbound connection and clean up on failure."""
        # Per-run cleanup intentionally does NOT pop inbound_pipes
        # here. Cleanup semantics across plugins will be revisited in
        # a dedicated session; for now leave the entry so a late
        # inbound connection has somewhere to land.
        timeout = getattr(self, "timeout", None)
        if timeout is not None:
            try:
                return await asyncio.wait_for(
                    asyncio.shield(self.inbound_pipes[self.plugin_id]),
                    timeout=timeout * 0.9,
                )
            except asyncio.TimeoutError:
                log("wait_for_inbound timed out after {0}s".format(timeout * 0.9))
                fut = self.inbound_pipes.get(self.plugin_id)
                if fut is not None and not fut.done():
                    fut.cancel()
                return None
        return await self.inbound_pipes[self.plugin_id]

    async def run(self, reply=None):
        """Execute the traversal strategy; subclasses must override this method."""
        log(
            "Plugin.run() called on base class - subclass should override this."
        )
