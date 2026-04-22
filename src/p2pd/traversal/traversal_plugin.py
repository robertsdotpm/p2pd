"""Base class and lifecycle helpers for traversal plugins."""
import asyncio
from .traversal_utils import *


class TraversalPlugin:
    """Abstract base class for P2P connection traversal strategy plugins."""

    def __init__(self):
        # type: () -> None
        self.result = asyncio.Future()
        self.plugin_id = to_s(rand_plain(15))
        self.has_reply = asyncio.Event()
        self.sig_pipe = None

    def set_addrs(self, src_map, dest_map):
        # type: (Dict[str, Any], Dict[str, Any]) -> None
        """Store the source and destination full address maps for this plugin."""
        self.src_map = src_map
        self.dest_map = dest_map

    def set_routing(self, af, src_info, dest_info, nic):
        # type: (Any, Dict[str, Any], Dict[str, Any], Any) -> None
        """Configure the address family, interface info, and NIC to use for this traversal."""
        self.af = af
        self.src_info = src_info
        self.dest_info = dest_info
        self.nic = nic

    def set_context(self, route_type, same_machine, set_bind, timeout):
        # type: (Any, bool, bool, int) -> None
        """Set the route type, same-machine flag, bind preference, and timeout for this plugin."""
        self.route_type = route_type
        self.same_machine = same_machine
        self.set_bind = set_bind
        self.timeout = timeout

        # Skip route determination -- not relevant.
        if not route_type:
            self.dest_info["ip"] = ""
            return

        """
        Determine the best destination IP to use
        for the connectivity technique based on
        addressing and relationships between the
        two machines (deep networking specific.)
        """
        selected = select_dest_ipr(
            self.af,
            same_machine,
            self.src_info,
            self.dest_info,
            [route_type],
            # can you make this case
            # run for all
            # try it
            set_bind,
        )
        self.dest_info["ip"] = str(selected) if selected is not None else ""

        # Need a destination address.
        # Possibly a different address type will work.
        if self.dest_info["ip"] == "":
            raise ValueError("Cannot select valid dest IP")

    def set_inbound_pipes(self, pipes, plugin_id=None):
        # type: (Dict[str, Any], Optional[str]) -> None
        """Attach the shared inbound-pipe dict and optionally override the plugin_id."""
        self.plugin_id = plugin_id or self.plugin_id
        self.inbound_pipes = pipes

    def set_send_signal_msg(self, send_signal_msg):
        # type: (Callable) -> None
        """Register the manager-level function plugins call to send signal messages."""
        self._send_signal_msg = send_signal_msg

    async def send_signal_msg(self, msg, relay_no=2):
        # type: (Any, int) -> Any
        """Delegate sending a signal message to the manager, passing self as the plugin context."""
        return await self._send_signal_msg(msg, self, relay_no)

    def register_inbound(self):
        # type: () -> None
        """Pre-register a Future in inbound_pipes so arriving connections are not missed."""
        # Register before sending any signal to avoid a race where the inbound
        # connection arrives before the future exists.
        self.inbound_pipes[self.plugin_id] = asyncio.Future()

    async def wait_for_inbound(self):
        # type: () -> Any
        """Await the Future for this plugin's inbound connection and clean up on failure."""
        try:
            return await self.inbound_pipes[self.plugin_id]
        except BaseException:
            self.inbound_pipes.pop(self.plugin_id, None)
            raise

    async def run(self, reply=None):
        # type: (Optional[Any]) -> None
        """Execute the traversal strategy; subclasses must override this method."""
        log(
            "TraversalPlugin.run() called on base class - subclass should override this."
        )
