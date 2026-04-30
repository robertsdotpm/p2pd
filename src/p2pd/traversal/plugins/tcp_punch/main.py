"""Traversal plugin for TCP/UDP hole punching."""
from typing import Any, Dict, Optional, Tuple
import asyncio
from aionetiface import log, NIC_BIND, EXT_BIND, SysClock, async_wrap_errors, cancel_task, shutdown_proc_pool
from ....protocol.proto_defs import P2P_PUNCH
from .proto import PunchMsg
from .boundary_lib import FAST_PUNCH_PARAMS, compute_rendezvous
from .punch_client import PunchClient
from .boundary_alloc import boundary_port_alloc
from .nat_predict_alloc import NATPredictAlloc
from .punch_process import start_punching_process
from .nat_predict import NATMapping
from ...traversal_plugin import TraversalPlugin
from ....node.node_utils import get_pp_executors

PLUGIN_CONF = {"timeout": 80}

# Protocol auto-registration: plugin_loader merges these into
# TraversalManager.sig_proto so PunchMsg dispatches without core
# proto_msg.py edits.
PROTO_MESSAGES = (
    # (msg_class, strategy_enum, ttl_seconds)
    # plugin_loader derives the wire name as "<plugin_name>.<class>"
    # and patches it onto the class -- no enum allocation needed.
    (PunchMsg, P2P_PUNCH, 20),
)


class PunchPlugin(TraversalPlugin):
    """Traversal plugin implementing TCP hole-punching via coordinated port prediction.

    Platform gotchas
    ----------------
    Windows Firewall and Windows Defender Real-Time Protection can silently
    block or delay the punched TCP connections even after the hole-punch
    exchange completes successfully.  Symptoms: PunchMsg exchange finishes
    normally (both sides log the rendezvous), the punch process runs, but
    the TCP connect never completes or the first data packet is dropped.

    During development / testing, disable both:
      - Windows Defender Firewall (all profiles: Domain, Private, Public)
      - Windows Security > Virus & threat protection > Real-time protection

    On production machines the right fix is an explicit inbound/outbound
    allow rule for the Python executable (or the specific port range used
    by the punch allocator).
    """

    # Punch is a NAT-traversal mechanism. NIC_BIND covers the same-LAN
    # case (kernel handles local routing for same-subnet peers); EXT_BIND
    # covers the cross-WAN case via predicted NAT mappings. LOOPBACK_BIND
    # has no NAT in the path and the predict_alloc / rendezvous machinery
    # produces no useful work over loopback, so we opt out of it
    # declaratively here -- auto_combos won't generate punch+LOOPBACK_BIND
    # combos for us.
    SUPPORTED_ROUTE_TYPES = (NIC_BIND, EXT_BIND)

    async def run(self, reply: Optional[Any] = None) -> None:
        """Coordinate the hole-punch exchange and launch the background punching process."""
        if self.plugin_id in self.completed_pipe_ids:
            return

        # --- Get or create the PunchClient for this session ---
        puncher = self.punch_clients.get(self.plugin_id)
        if puncher is None:
            # First call: build a PunchClient with routing, timing, and port allocators.
            puncher, stuns = await self.setup_puncher_client(reply)
            if puncher is None:
                log("PunchPlugin: no STUN clients available; aborting punch.")
                return

            # A concurrent run() may have raced through the await above and already
            # registered a client.  Reuse it to avoid a duplicate punching process.
            puncher = self.punch_clients.get(self.plugin_id) or puncher
            if self.plugin_id not in self.punch_clients:
                puncher = await self.configure_puncher_process(puncher, stuns)

        # --- Advance the NAT traversal exchange ---
        # Each call computes the next round of port predictions and checks
        # whether both sides have exchanged enough mappings to attempt punching.
        outgoing_msg = await self.advance_punching_protocol(
            puncher, reply, puncher.punch_time
        )

        # None signals the exchange is complete; the background punch process
        # takes it from here.
        if outgoing_msg is None:
            return

        # --- Send our port predictions to the peer ---
        await self.send_signal_msg(outgoing_msg)

    async def setup_puncher_client(self, reply: Optional[Any]) -> Tuple[Optional[Any], Optional[Any]]:
        """
        Determines the source/destination addresses and the decider IP,
        creates a new PunchClient, and sets the coordinated time references.
        """
        if_index = self.src_info["if_index"]
        # Safe two-level lookup: load_stun_clients populates entries
        # only for the (af, if_index) combinations that successfully
        # resolved a STUN server during node startup. On hosts where
        # v6 STUN never came up (XP / Vista without a working v6
        # path) the inner dict is missing the if_index entirely, and
        # bare self.stun_clients[af][if_index] raises KeyError before
        # the "no STUN clients loaded" guard below ever runs.
        stuns = self.stun_clients.get(self.af, {}).get(if_index, [])

        # Skip if no STUN clients loaded.
        if not stuns:
            return None, None

        # Determine IP addresses via routing.
        dest_ip = self.dest_info["ip"]

        # Defensive: punching to our own NIC IP is a malformed
        # configuration -- the rendezvous would loop back through the
        # local stack and the port-prediction state machine has
        # historically crashed the whole node when it tries it. The
        # combo generator should drop this via pair_distinct, but if
        # it slips through (signaled-from-peer plugin instances bypass
        # the local generator), bail cleanly with a logged message
        # rather than tearing down the loop.
        try:
            src_nic_ip = self.src_info.get("nic")
        except AttributeError:
            src_nic_ip = None
        if src_nic_ip is not None:
            try:
                if str(src_nic_ip) == str(dest_ip):
                    log("PunchPlugin: dest matches own NIC IP ({0}); aborting".format(dest_ip))
                    return None, None
            except (TypeError, ValueError):
                pass

        route = await self.nic.route(self.af).bind()
        if "fe80" == dest_ip[:4]:
            # Use link-local source for link-local destination
            src_ip = str(route.link_locals[0])
        else:
            # Use the interface's local IP
            src_ip = route.nic()

        # Determine the decider IP for master/slave role selection.
        if self.route_type == NIC_BIND:
            decider_ip = src_ip
        else:
            decider_ip = route.ext()

        # Create and configure the PunchClient.
        # FAST_PUNCH_PARAMS is used for network-protocol punching: the punch_time
        # is communicated between peers via PunchMsg so we do not need the large
        # WINDOW / MAX_CLOCK_ERROR values used by the CLI standalone mode.  The
        # tight window (6 s) and short coordinator_delay (0.5 s) cut total punch
        # latency roughly in half compared to the conservative CLI defaults.
        puncher = PunchClient(
            dest_ip,
            src_ip,
            decider_ip,
            self.nic.id,
            same_machine=self.same_machine,
            params=FAST_PUNCH_PARAMS,
        )

        # Set coordinated time references.
        timestamp = self.sys_clock.time()
        puncher.set_timestamp(timestamp)

        # Calculate a future timestamp to use as the punch time.
        # Use the timing constants from the puncher's params so that the
        # rendezvous window matches the params preset (e.g. FAST_PUNCH_PARAMS).
        p = puncher.params
        _, punch_time = compute_rendezvous(
            timestamp,
            window=p["window"],
            min_run_window=p["min_run_window"],
            max_error=p["max_clock_error"],
        )

        # Set punch time.
        puncher.set_punch_time(punch_time)

        # Deterministic predictions based on boundary math.
        # PunchClient.add_port_allocator forwards self.params to the allocator
        # so it uses the same window / error constants for bucket derivation.
        puncher.add_port_allocator(boundary_port_alloc)

        # Return the new puncher and the STUN clients
        return puncher, stuns

    async def configure_puncher_process(self, puncher: Any, stuns: Any) -> Any:
        """
        Initializes the NAT Prediction Allocator, saves the PunchClient,
        and schedules the delayed asynchronous punching process.
        """
        # Register the puncher so subsequent run() calls can find it.
        self.punch_clients[self.plugin_id] = puncher

        # Initialize the NAT prediction allocator.
        # Note: this just wraps nat_predict.py.
        # There's an aweful lot of bloat just to use code thats already written.
        self.nat_alloc = NATPredictAlloc(stuns)
        self.nat_alloc.set_nat_info(self.src_info["nat"], self.dest_info["nat"])
        self.nat_alloc.set_punch_mode(self.same_machine, self.dest_info["ip"])

        # Schedule the punching process with a short delay.
        if self.plugin_id not in self.punch_proc:
            self.punch_proc[self.plugin_id] = asyncio.create_task(
                async_wrap_errors(self.delayed_start_punching_proc(self.nic, puncher))
            )

        return puncher

    async def advance_punching_protocol(self, puncher: Any, reply: Optional[Any], punch_time: int) -> Optional[Any]:
        """Compute the next round of port predictions and return an outgoing PunchMsg, or None when done."""
        # Convert raw mappings from the peer into internal objects.
        recv_mappings = None
        if reply is not None:
            recv_mappings = [NATMapping(m) for m in reply.payload.mappings]
            assert recv_mappings

        # Compute the next round of port predictions.
        port_alloc, is_end = await self.nat_alloc.port_alloc(recv_mappings)
        puncher.port_allocs += port_alloc

        # End of protocol.
        if is_end == 1:
            return None

        # Gather our mappings and build the outgoing control message.
        mappings = [m.to_json() for m in self.nat_alloc.send_mappings]
        msg = PunchMsg(
            {
                "payload": {
                    "punch_mode": self.nat_alloc.punch_mode,
                    "mappings": mappings,
                    "ntp": punch_time,
                },
            }
        )

        msg.meta.plugin_name = "tcp_punch"
        return msg

    # ... (other methods, including delayed_start_punching_proc) ...
    async def delayed_start_punching_proc(self, nic: Any, puncher: Any) -> None:
        """Wait a short coordinator delay then launch the punching process and resolve the result."""
        # Wait for the peer to receive our message and set up its own process.
        # The delay is kept short when using FAST_PUNCH_PARAMS because the
        # rendezvous window is small and synchronised via sleep_until().
        coordinator_delay = puncher.params.get("coordinator_delay", 2.0)
        try:
            await asyncio.sleep(coordinator_delay)
            pipe = await start_punching_process(
                nic,
                puncher,
                self.stop_reader,
                self.proc_pool,
            )

            # Guard against a second concurrent call resolving the same future,
            # which would raise asyncio.InvalidStateError.
            if not self.result.done():
                self.result.set_result(pipe)
        finally:
            # Always remove shared state so subsequent attempts start clean.
            # This runs on normal completion, cancellation, and exceptions.
            self.punch_proc.pop(self.plugin_id, None)
            self.punch_clients.pop(self.plugin_id, None)
            self.completed_pipe_ids.add(self.plugin_id)

    async def close(self) -> None:
        """Cancel any in-flight punch task and remove this plugin's shared state.

        Safe to call multiple times: pop() is a no-op when the key is absent
        and task/future guards check done() before acting.
        """
        task = self.punch_proc.pop(self.plugin_id, None)
        self.punch_clients.pop(self.plugin_id, None)
        await cancel_task(task)

        # Cancel the result future if nobody resolved it (e.g. outer timeout).
        if not self.result.done():
            self.result.cancel()
        self.completed_pipe_ids.add(self.plugin_id)


class PunchPluginFactory:
    """Creates and configures PunchPlugin instances sharing STUN clients and process pools."""

    def __init__(
self,
        stun_clients: Any,
        sys_clock: Optional[Any] = None,
        punch_clients: Optional[Dict[str, Any]] = None,
        proc_pool: Optional[Any] = None,
    ) -> None:
        self.stun_clients = stun_clients
        self.sys_clock = sys_clock or SysClock(None, 0.1)
        self.proc_pool = proc_pool
        self.max_workers = 0
        self.punch_clients = punch_clients if punch_clients is not None else {}
        self.punch_proc = {}
        self.completed_pipe_ids = set()

    @classmethod
    async def create(cls, stun_clients: Any, sys_clock: Any) -> "PunchPluginFactory":
        """Async factory that allocates a process pool executor and returns a ready factory."""
        factory = cls(stun_clients, sys_clock)
        factory.max_workers, factory.proc_pool = await get_pp_executors()
        factory.active_punchers = 0
        return factory

    def build_plugin(self) -> PunchPlugin:
        """Create a new PunchPlugin wired to this factory's shared STUN clients and state."""
        plugin = PunchPlugin()
        plugin.stun_clients = self.stun_clients
        plugin.sys_clock = self.sys_clock
        plugin.proc_pool = self.proc_pool
        plugin.punch_clients = self.punch_clients
        plugin.punch_proc = self.punch_proc
        plugin.completed_pipe_ids = self.completed_pipe_ids
        return plugin

    async def close(self) -> None:
        """Shut down the process pool executor used for running punch workers."""
        if not self.proc_pool:
            return
        await shutdown_proc_pool(self.proc_pool)
        self.proc_pool = None


async def setup_plugin(node):
    """Create the punch factory; returns None if punching is disabled in node.conf."""
    if not node.conf.get("enable_punching", True):
        return None
    factory = await PunchPluginFactory.create(node.stun_clients, node.sys_clock)
    node.resources.punch_factory = factory
    node.resources.register(factory)
    return factory
