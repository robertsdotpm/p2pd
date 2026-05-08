"""Traversal plugin for TCP hole punching via coordinated port prediction.

Timeout budget (PLUGIN_CONF["timeout"] = 180):
  180 s = max-rendezvous-wait (window=42 + max_clock_error=20 ≈ 62 s)
        + primary spray (~3 s) + primary monitor (~3 s)
        + secondary rendezvous wait (window=42 s) for two-bucket dual-fire
        + secondary spray (~3 s) + secondary monitor (~3 s)
        + worker dispatch / engine setup overhead (varies by host,
          ~5-15 s on slow stacks)
        + the post-punch reverse-bridge accept (typically <1 s)
        + a safety margin for slow stacks (XP/Vista) so the run_plugin
          wait_for doesn't cancel the awaiting reverse_server.accept
          before the worker has had a chance to connect back. The
          previous 80 s left only ~10 s margin which v13's vista-from-xp
          ate, manifesting as WinError 10061 on the worker's connect-
          back to a listener that had just been torn down by the
          cancellation propagating from the timeout firing.

PROTO_MESSAGES is consumed by plugin_loader: it merges each entry into
TraversalManager.sig_proto so PunchMsg dispatches without core
proto_msg.py edits.  Each tuple is (msg_class, strategy_enum, ttl_secs);
plugin_loader derives the wire name as "<plugin_name>.<class>" and
patches it onto the class -- no enum allocation needed.

route_types: NIC_BIND covers the same-LAN case (kernel handles local
routing for same-subnet peers); EXT_BIND covers the cross-WAN case via
predicted NAT mappings.  LOOPBACK_BIND has no NAT in the path and the
predict_alloc / rendezvous machinery produces no useful work over
loopback, so we opt out of it declaratively -- auto_combos won't
generate punch+LOOPBACK_BIND combos for us.

Platform gotchas: Windows Firewall and Windows Defender Real-Time
Protection can silently block or delay the punched TCP connections
even after the hole-punch exchange completes successfully.  Symptoms:
PunchMsg exchange finishes normally (both sides log the rendezvous),
the punch process runs, but the TCP connect never completes or the
first data packet is dropped.  During development / testing, disable
both Windows Defender Firewall (all profiles) and Windows Security >
Virus & threat protection > Real-time protection.  On production
machines the right fix is an explicit inbound/outbound allow rule for
the Python executable (or the specific port range used by the punch
allocator).
"""
from typing import Any, Dict, Optional, Tuple
import asyncio
from aionetiface import log, NIC_BIND, EXT_BIND, SysClock, async_wrap_errors, cancel_task, shutdown_proc_pool
from ....protocol.proto_defs import P2P_PUNCH
from .proto import PunchMsg
from .boundary_lib import FAST_PUNCH_PARAMS, compute_rendezvous
from .punch_client import PunchClient
from .boundary_alloc import boundary_port_alloc
from .nat_predict_alloc import NATPredictAlloc
from .punch_defs import TCP_PUNCH_LAN
from .punch_process import start_punching_process
from .tcp_punch_utils import log_time_wait_residue
from .nat_predict import NATMapping
from ...traversal_plugin import TraversalPlugin
from ...strategy_registry import register
from ....node.node_utils import get_pp_executors

@register(phase="punch")
class PunchPlugin(TraversalPlugin):
    """Traversal plugin implementing TCP hole-punching via coordinated port prediction."""

    name = "tcp_punch"
    transport = "tcp"
    route_types = (NIC_BIND, EXT_BIND)
    conf = {"timeout": 180}
    proto_messages = (
        (PunchMsg, P2P_PUNCH, 20),
    )

    @classmethod
    async def setup(cls, node):
        if not node.conf.get("enable_punching", True):
            return None
        factory = await PunchPluginFactory.create(node.stun_clients, node.sys_clock)
        node.resources.punch_factory = factory
        node.resources.register(factory)
        return factory

    async def run(self, reply: Optional[Any] = None) -> None:
        """Coordinate the hole-punch exchange and launch the background punching process."""
        print("[PUNCH-RUN] enter plugin_id={0} reply={1} completed={2}".format(
            self.plugin_id, reply is not None,
            self.plugin_id in self.completed_pipe_ids,
        ), flush=True)
        log("[PUNCH-RUN] enter plugin_id={0} reply={1} completed={2}".format(
            self.plugin_id,
            reply is not None,
            self.plugin_id in self.completed_pipe_ids,
        ))
        if self.plugin_id in self.completed_pipe_ids:
            print("[PUNCH-RUN] already completed; returning early plugin_id={0}".format(
                self.plugin_id,
            ), flush=True)
            log("[PUNCH-RUN] already completed; returning early plugin_id={0}".format(
                self.plugin_id,
            ))
            return

        # --- Get or create the PunchClient for this session ---
        puncher = self.punch_clients.get(self.plugin_id)
        if puncher is None:
            # First call: build a PunchClient with routing, timing, and port allocators.
            print("[PUNCH-RUN] first call; setup_puncher_client plugin_id={0}".format(
                self.plugin_id,
            ), flush=True)
            log("[PUNCH-RUN] first call; setup_puncher_client plugin_id={0}".format(
                self.plugin_id,
            ))
            try:
                puncher, stuns = await self.setup_puncher_client(reply)
            except BaseException as exc:
                print("[PUNCH-RUN] setup_puncher_client raised {0}: {1}".format(
                    type(exc).__name__, exc,
                ), flush=True)
                raise
            if puncher is None:
                print("[PUNCH-RUN] PunchPlugin: no STUN clients available; aborting.", flush=True)
                log("[PUNCH-RUN] PunchPlugin: no STUN clients available; aborting punch.")
                return
            print("[PUNCH-RUN] setup_puncher_client OK; n_stuns={0}".format(
                len(stuns) if stuns else 0,
            ), flush=True)

            # A concurrent run() may have raced through the await above and already
            # registered a client.  Reuse it to avoid a duplicate punching process.
            puncher = self.punch_clients.get(self.plugin_id) or puncher
            if self.plugin_id not in self.punch_clients:
                print("[PUNCH-RUN] configure_puncher_process plugin_id={0}".format(
                    self.plugin_id,
                ), flush=True)
                log("[PUNCH-RUN] configure_puncher_process plugin_id={0}".format(
                    self.plugin_id,
                ))
                try:
                    puncher = await self.configure_puncher_process(puncher, stuns)
                except BaseException as exc:
                    print("[PUNCH-RUN] configure_puncher_process raised {0}: {1}".format(
                        type(exc).__name__, exc,
                    ), flush=True)
                    raise
                print("[PUNCH-RUN] configure_puncher_process OK", flush=True)
        else:
            print("[PUNCH-RUN] reusing existing puncher plugin_id={0}".format(
                self.plugin_id,
            ), flush=True)
            log("[PUNCH-RUN] reusing existing puncher plugin_id={0}".format(
                self.plugin_id,
            ))

        # --- Advance the NAT traversal exchange ---
        # Each call computes the next round of port predictions and checks
        # whether both sides have exchanged enough mappings to attempt punching.
        print("[PUNCH-RUN] advance_punching_protocol enter punch_time={0}".format(
            getattr(puncher, "punch_time", "?"),
        ), flush=True)
        try:
            outgoing_msg = await self.advance_punching_protocol(
                puncher, reply, puncher.punch_time
            )
        except BaseException as exc:
            print("[PUNCH-RUN] advance_punching_protocol raised {0}: {1}".format(
                type(exc).__name__, exc,
            ), flush=True)
            raise
        print("[PUNCH-RUN] advance_punching_protocol returned outgoing={0}".format(
            outgoing_msg is not None,
        ), flush=True)

        # None signals the exchange is complete; the background punch process
        # takes it from here.
        if outgoing_msg is None:
            print("[PUNCH-RUN] advance returned None; exchange done plugin_id={0}".format(
                self.plugin_id,
            ), flush=True)
            log("[PUNCH-RUN] advance returned None; exchange done plugin_id={0}".format(
                self.plugin_id,
            ))
            return

        # --- Send our port predictions to the peer ---
        print("[PUNCH-RUN] sending outgoing PunchMsg plugin_id={0}".format(
            self.plugin_id,
        ), flush=True)
        log("[PUNCH-RUN] sending outgoing PunchMsg plugin_id={0}".format(self.plugin_id))
        await self.send_signal_msg(outgoing_msg)
        print("[PUNCH-RUN] sent OK plugin_id={0}".format(self.plugin_id), flush=True)

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
            # Use link-local source for link-local destination.
            src_ip = str(route.link_locals[0])
            # Append the local NIC scope_id to both addresses so the
            # Windows connect_ex / bind paths know which interface to
            # use. Linux's getaddrinfo accepts bare fe80:: and falls
            # back to the routing table; Windows does not -- without
            # the %ifindex the SYN never leaves and the listener log
            # stays silent. On the bind side resolve_bind_ip already
            # patches src_ip via ip6_patch_bind_ip, but the engine's
            # raw connect_ex(dest_ip, port) gets no such treatment,
            # so we have to bake the scope into dest_ip here. Strips
            # any existing % first to keep the patch idempotent.
            # Interface.get_nic_id(af) returns the right ifindex per
            # AF -- on XP that's the v6-side index from TCPIP6 (vs
            # the v4 index in nic.id); everywhere else the indices
            # are unified so it returns the same value.
            from aionetiface.net.bind.bind_utils import ip6_patch_bind_ip
            v6_scope = self.nic.get_nic_id(self.af)
            dest_ip = ip6_patch_bind_ip(dest_ip.split("%", 1)[0], v6_scope)
            src_ip = ip6_patch_bind_ip(src_ip.split("%", 1)[0], v6_scope)
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
            self.nic.get_nic_id(self.af),
            same_machine=self.same_machine,
            params=FAST_PUNCH_PARAMS,
            our_os=(self.src_map.get("os") if self.src_map else None),
            their_os=(self.dest_map.get("os") if self.dest_map else None),
        )

        # Set coordinated time references.
        timestamp = self.sys_clock.time()
        puncher.set_timestamp(timestamp)

        # Calculate the primary + secondary punch times for two-bucket
        # overlap dual-fire.  See PunchClient.run_engine for the strategy:
        # when the connector and listener call compute_rendezvous on
        # opposite sides of a bucket boundary they pick adjacent buckets,
        # but their {primary, primary+1} candidate sets always overlap on
        # one common bucket -- so firing at both rendezvous in sequence
        # guarantees the peer-pair lands on a synchronised fire moment.
        # The secondary is exactly one WINDOW past the primary; both peers
        # compute the same window arithmetic so they agree on the second
        # rendezvous as well.
        p = puncher.params
        _, punch_time = compute_rendezvous(
            timestamp,
            window=p["window"],
            min_run_window=p["min_run_window"],
            max_error=p["max_clock_error"],
        )
        secondary_punch_time = punch_time + p["window"]
        print("[CLOCK] tcp_punch my_now={0} punch_time={1} delta={2} window={3} max_clock_error={4}".format(
            timestamp, punch_time, punch_time - timestamp, p["window"], p["max_clock_error"],
        ))

        puncher.set_punch_time(punch_time, secondary_punch_time=secondary_punch_time)

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
        # For LAN, STUN is useless (returns each side's own port).
        # Boundary ports from setup_puncher_client already align both sides.
        # Send one empty PunchMsg to trigger the recipient; return None on reply.
        if self.nat_alloc.punch_mode == TCP_PUNCH_LAN:
            if reply is not None:
                return None
            msg = PunchMsg(
                {
                    "payload": {
                        "punch_mode": self.nat_alloc.punch_mode,
                        "mappings": [],
                        "ntp": punch_time,
                    },
                }
            )
            msg.meta.plugin_name = "tcp_punch"
            return msg

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
        print("[PUNCH-DELAY] enter plugin_id={0} delay={1}s".format(
            self.plugin_id, coordinator_delay,
        ), flush=True)
        log("[PUNCH-DELAY] enter plugin_id={0} delay={1}s".format(
            self.plugin_id, coordinator_delay,
        ))
        try:
            await asyncio.sleep(coordinator_delay)
            print("[PUNCH-DELAY] sleep done; calling start_punching_process plugin_id={0}".format(
                self.plugin_id,
            ), flush=True)
            log("[PUNCH-DELAY] sleep done; calling start_punching_process plugin_id={0}".format(
                self.plugin_id,
            ))
            pipe = await start_punching_process(
                nic,
                puncher,
                self.stop_reader,
                self.proc_pool,
                node_msg_cb=getattr(self, "node_msg_cb", None),
            )
            print("[PUNCH-DELAY] start_punching_process returned plugin_id={0} pipe={1}".format(
                self.plugin_id, pipe is not None,
            ), flush=True)
            log("[PUNCH-DELAY] start_punching_process returned plugin_id={0} pipe={1}".format(
                self.plugin_id, pipe is not None,
            ))

            # Guard against a second concurrent call resolving the same future,
            # which would raise asyncio.InvalidStateError.
            if not self.result.done():
                self.result.set_result(pipe)
        except asyncio.CancelledError:
            print("[PUNCH-DELAY] CANCELLED plugin_id={0}".format(self.plugin_id), flush=True)
            log("[PUNCH-DELAY] CANCELLED plugin_id={0}".format(self.plugin_id))
            raise
        except Exception as exc:  # pylint: disable=broad-except
            print("[PUNCH-DELAY] EXCEPTION plugin_id={0} {1}: {2}".format(
                self.plugin_id, type(exc).__name__, repr(exc),
            ), flush=True)
            log("[PUNCH-DELAY] EXCEPTION plugin_id={0} {1}: {2}".format(
                self.plugin_id, type(exc).__name__, repr(exc),
            ))
            raise
        finally:
            # Per-run cleanup intentionally does NOT pop punch_proc /
            # punch_clients here. Popping mid-run lets a peer's follow-up
            # signal re-enter run() and spawn a SECOND engine task with
            # the same predicted ports while the first worker is still
            # holding them -- bind_punch_sockets then fails 4/4 with
            # EADDRINUSE 10048 and the bridge is wired to a dead engine.
            # close() is the only place that pops; cleanup semantics
            # will be revisited in a dedicated session.
            log("[PUNCH-DELAY] finally plugin_id={0}".format(self.plugin_id))
            self.completed_pipe_ids.add(self.plugin_id)
            # Post-mortem: are any of our boundary 4-tuples still in
            # TIME_WAIT? With SO_LINGER {1,0} on punch sockets the
            # answer should always be 0. Any non-zero count points at
            # a code path that closed without the linger sockopt.
            await log_time_wait_residue(getattr(puncher, "src_ip", None))

    async def close(self) -> None:
        """Cancel any in-flight punch task and remove this plugin's shared state.

        Safe to call multiple times: pop() is a no-op when the key is absent
        and task/future guards check done() before acting.
        """
        task = self.punch_proc.pop(self.plugin_id, None)
        self.punch_clients.pop(self.plugin_id, None)
        log("[PUNCH-CLOSE] plugin_id={0} task_was_pending={1}".format(
            self.plugin_id,
            task is not None and not task.done() if task else False,
        ))
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


