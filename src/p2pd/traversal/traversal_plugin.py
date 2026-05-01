"""Base class and lifecycle helpers for traversal plugins."""
from typing import Any, Callable, Dict, Optional
import asyncio
from .traversal_utils import select_dest_ipr
from aionetiface import to_s, rand_plain, log, NIC_BIND, EXT_BIND, LOOPBACK_BIND


class TraversalPlugin:
    """Abstract base class for P2P connection traversal strategy plugins."""

    # Route types this plugin will accept combos for. auto_combos /
    # auto_combo_batches consult this to skip combos a plugin would
    # just no-op on. Default: every route_type is fair game; plugins
    # override the tuple to opt out of specific paths.
    SUPPORTED_ROUTE_TYPES = (NIC_BIND, LOOPBACK_BIND, EXT_BIND)

    def __init__(self) -> None:
        self.result = asyncio.Future()
        self.plugin_id = to_s(rand_plain(15))
        self.has_reply = asyncio.Event()
        self.sig_pipe = None
        self.src_map = None
        self.dest_map = None
        self.af = None
        self.src_info = None
        self.dest_info = None
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
        self._send_signal_msg = None

    def set_addrs(self, src_map: Dict[str, Any], dest_map: Dict[str, Any]) -> None:
        """Store the source and destination full address maps for this plugin."""
        self.src_map = src_map
        self.dest_map = dest_map

    def set_routing(self, af: Any, src_info: Dict[str, Any], dest_info: Dict[str, Any], nic: Any) -> None:
        """Configure the address family, interface info, and NIC to use for this traversal."""
        self.af = af
        self.src_info = src_info
        self.dest_info = dest_info
        self.nic = nic

    def set_context(self, route_type: Any, same_machine: bool, set_bind: bool, timeout: int) -> None:
        """Set the route type, same-machine flag, bind preference, and timeout for this plugin.

        When route_type / af / src_info / dest_info are unconstrained
        (any-pathway mode -- used by reverse_connect when the responder
        is free to pick), we skip dest IP selection entirely. The
        plugin (e.g. reverse_connect) is responsible for handling the
        unconstrained case in its run() method.
        """
        self.route_type = route_type
        self.same_machine = same_machine
        self.set_bind = set_bind
        self.timeout = timeout

        # Skip route determination -- not relevant.
        if not route_type or self.dest_info is None or self.src_info is None or self.af is None:
            if self.dest_info is not None:
                self.dest_info["ip"] = ""
            return

        # Determine the best destination IP to use
        # for the connectivity technique based on
        # addressing and relationships between the
        # two machines (deep networking specific.)
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
        print("[CTX-DBG] route_type={0} af={1} same_machine={2} src_loopback={3} dest_loopback={4} dest_nic={5} dest_ext={6} -> dest_ip={7!r}".format(
            route_type, self.af, same_machine,
            self.src_info.get("loopback"),
            self.dest_info.get("loopback"),
            self.dest_info.get("nic"),
            self.dest_info.get("ext"),
            self.dest_info["ip"],
        ))

        # Need a destination address.
        # Possibly a different address type will work.
        if self.dest_info["ip"] == "":
            raise ValueError("Cannot select valid dest IP")

    def set_inbound_pipes(self, pipes: Dict[str, Any], plugin_id: Optional[str] = None) -> None:
        """Attach the shared inbound-pipe dict and optionally override the plugin_id."""
        self.plugin_id = plugin_id or self.plugin_id
        self.inbound_pipes = pipes

    def set_send_signal_msg(self, send_signal_msg: Callable) -> None:
        """Register the manager-level function plugins call to send signal messages."""
        self._send_signal_msg = send_signal_msg

    async def send_signal_msg(self, msg: Any, relay_no: int = 2) -> Any:
        """Delegate sending a signal message to the manager, passing self as the plugin context."""
        return await self._send_signal_msg(msg, self, relay_no)

    def register_inbound(self) -> None:
        """Pre-register a Future in inbound_pipes so arriving connections are not missed."""
        # Register before sending any signal to avoid a race where the inbound
        # connection arrives before the future exists.
        self.inbound_pipes[self.plugin_id] = asyncio.Future()

    async def wait_for_inbound(self) -> Any:
        """Await the Future for this plugin's inbound connection and clean up on failure."""
        # Per-run cleanup intentionally does NOT pop inbound_pipes
        # here. Cleanup semantics across plugins will be revisited in
        # a dedicated session; for now leave the entry so a late
        # inbound connection has somewhere to land.
        return await self.inbound_pipes[self.plugin_id]

    async def run(self, reply: Optional[Any] = None) -> None:
        """Execute the traversal strategy; subclasses must override this method."""
        log(
            "TraversalPlugin.run() called on base class - subclass should override this."
        )
