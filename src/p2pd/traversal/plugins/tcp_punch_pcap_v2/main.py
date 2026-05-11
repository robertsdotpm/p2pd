"""Parity port of the tcp_punch plugin on top of a userspace pcap stack.

Inherits orchestration verbatim from `..tcp_punch`:
  - boundary_lib.compute_rendezvous + FAST_PUNCH_PARAMS for clock-
    bucket-aligned punch_time selection.
  - PunchClient for STUN-mapping + port-allocator wiring.
  - NATPredictAlloc for the per-NAT prediction state machine.
  - PunchMsg (shared wire) for the signal-channel exchange. We label
    outbound messages with plugin_name "tcp_punch" so this plugin
    inter-ops on the wire with peers running plain tcp_punch.

Replaces:
  - tcp_selector_punch_engine + the ProcessPoolExecutor / selector_proxy
    bridge in tcp_punch.punch_process. Instead we drive
    pcap_engine.pcap_selector_punch_engine directly in the main
    asyncio loop -- the userspace TCP stack is async-native, so the
    "blocking spray in a worker thread" rationale doesn't apply.

  - The Windows-only netsh firewall mutation in tcp_punch_pcap.firewall.
    We use firewall_helper.install_block_ports / remove_block_ports
    which mirrors tests/cross_nat_pcap_smoke/host_firewall.py: per-OS
    iptables / pf / netsh-noop, idempotent, with the install/finally-
    remove pattern to guarantee restore.

Scope guard: setup() returns None unless the running OS has both a
working pcap backend AND a known firewall-install path. This keeps
the plugin disabled on platforms where the substrate is incomplete
(macOS / BSD pcap permission paths are pending environment work).
"""
import asyncio
import sys

from aionetiface import (
    log, EXT_BIND, TCP, SysClock, async_wrap_errors, cancel_task,
    shutdown_proc_pool,
)

from ....protocol.proto_defs import P2P_PUNCH
from ...strategy_registry import register
from ...traversal_plugin import Plugin

from ..tcp_punch.proto import PunchMsg
from ..tcp_punch.boundary_lib import FAST_PUNCH_PARAMS, compute_rendezvous
from ..tcp_punch.boundary_alloc import boundary_port_alloc
from ..tcp_punch.punch_client import PunchClient
from ..tcp_punch.nat_predict_alloc import NATPredictAlloc
from ..tcp_punch.nat_predict import NATMapping
from ..tcp_punch.punch_defs import TCP_PUNCH_LAN

from .pcap_engine import pcap_selector_punch_engine
from .firewall_helper import install_block_ports, remove_block_ports


def is_pcap_substrate_eligible_os():
    """True when the local OS has a verified pcap+firewall code path.

    Linux (iptables) and Windows-XP / Windows-2000 (firewall_helper
    no-op + existing host firewall rules) are the verified paths in
    the smoke test. macOS / BSD pf paths exist but are not wired into
    the test matrix yet; they fall through here so the v2 plugin
    refuses to load on those OSes by default.
    """
    if sys.platform.startswith("linux"):
        return True
    # XP / 2000 -- legacy NT-5 kernel needs the pcap bypass. We rely
    # on the existing host firewall rather than mutating it.
    if sys.platform.startswith("win"):
        try:
            from aionetiface import os_id
            local_os = os_id()
        except ImportError:
            return False
        if not local_os:
            return False
        return (
            local_os.startswith("Windows-XP")
            or local_os.startswith("Windows-2000")
        )
    return False


@register(phase="punch")
class PunchPcapV2Plugin(Plugin):
    """tcp_punch with the kernel-socket spray replaced by pcap Connections."""

    name = "tcp_punch_pcap_v2"
    transport = TCP
    # Same routing as the original tcp_punch_pcap: only EXT_BIND.
    # NIC_BIND / LOOPBACK_BIND don't need the userspace bypass.
    route_types = (EXT_BIND,)
    # Tighter than tcp_punch's 180 s: the userspace handshake either
    # converges in <2 s once both sides fire or it won't converge at
    # all (no NAT timer extension to play for, no XP reverse-bridge
    # accept tail to budget for).
    conf = {"timeout": 60}
    # DO NOT register PunchMsg here. tcp_punch already registers it
    # under wire name "tcp_punch.PunchMsg"; listing it here would
    # either collide or create a second wire name and break interop.
    proto_messages = ()

    @classmethod
    async def setup(cls, node):
        if not node.conf.get("enable_punching", True):
            return None
        if not is_pcap_substrate_eligible_os():
            log("tcp_punch_pcap_v2: local OS not eligible; disabling")
            return None
        try:
            from aionetiface.net.pcap import get_backend, PcapUnavailableError
        except ImportError:
            log("tcp_punch_pcap_v2: pcap import failed; disabling")
            return None
        try:
            factory = get_backend()
        except PcapUnavailableError as exc:
            log("tcp_punch_pcap_v2: pcap unavailable ({0}); disabling".format(
                exc,
            ))
            return None
        if not factory.available():
            log("tcp_punch_pcap_v2: pcap factory unavailable; disabling")
            return None
        log("tcp_punch_pcap_v2: ready -- pcap library = {0}".format(
            factory.library_version(),
        ))
        factory_holder = PunchPcapV2Factory.create(
            node.stun_clients, node.sys_clock,
        )
        node.resources.punch_pcap_v2_factory = factory_holder
        node.resources.register(factory_holder)
        return factory_holder

    async def run(self, reply=None):
        """Coordinate the bucket-aligned punch exchange and dispatch the
        pcap-driven spray on the second message."""
        print("[PUNCH-PCAPV2-RUN] enter plugin_id={0} reply={1} completed={2}".format(
            self.plugin_id, reply is not None,
            self.plugin_id in self.completed_pipe_ids,
        ), flush=True)
        if self.plugin_id in self.completed_pipe_ids:
            print("[PUNCH-PCAPV2-RUN] already completed; returning", flush=True)
            return

        # Pre-bucket clock-truth sanity check (verbatim shape from tcp_punch).
        if reply is not None:
            peer_tx = getattr(reply.payload, "tx_unix", 0)
            if peer_tx:
                peer_unc = float(getattr(
                    reply.payload, "clock_uncertainty", 0.0,
                ))
                our_unc = float(getattr(self.sys_clock, "uncertainty", 0.0))
                max_err = FAST_PUNCH_PARAMS.get("max_clock_error", 4)
                our_now = int(self.sys_clock.time())
                SIGNAL_LATENCY_BUDGET = 10
                budget = our_unc + peer_unc + max_err + SIGNAL_LATENCY_BUDGET
                skew = abs(our_now - peer_tx)
                if skew > budget:
                    log("[PUNCH-PCAPV2-RUN] pre-bucket bailout: skew={0}s "
                        "budget={1}s".format(skew, int(budget)))
                    if not self.result.done():
                        self.result.set_result(None)
                    return

        # Per-session PunchClient
        puncher = self.punch_clients.get(self.plugin_id)
        if puncher is None:
            try:
                puncher, stuns = await self.setup_puncher_client(reply)
            except BaseException as exc:
                print("[PUNCH-PCAPV2-RUN] setup_puncher_client raised "
                      "{0}: {1}".format(type(exc).__name__, exc), flush=True)
                raise
            if puncher is None:
                print("[PUNCH-PCAPV2-RUN] no STUN clients; aborting", flush=True)
                if not self.result.done():
                    self.result.set_result(None)
                return
            puncher = self.punch_clients.get(self.plugin_id) or puncher
            if self.plugin_id not in self.punch_clients:
                puncher = await self.configure_puncher_process(puncher, stuns)

        # Advance the NAT exchange.
        outgoing_msg = await self.advance_punching_protocol(
            puncher, reply, puncher.punch_time,
        )
        if outgoing_msg is None:
            print("[PUNCH-PCAPV2-RUN] exchange done", flush=True)
            return
        await self.send_signal(outgoing_msg)

    async def setup_puncher_client(self, reply):
        """Build the PunchClient + load STUN. Same shape as tcp_punch."""
        if_index = self.src["if_index"]
        stuns = self.stun_clients.get(self.af, {}).get(if_index, [])
        if not stuns:
            from aionetiface import (
                get_n_stun_clients, RFC5389, USE_MAP_NO,
            )
            from ..tcp_punch.punch_defs import PUNCH_CONF
            try:
                retry = await asyncio.wait_for(
                    get_n_stun_clients(
                        af=self.af, n=USE_MAP_NO, mode=RFC5389,
                        interface=self.nic, proto=TCP, conf=PUNCH_CONF,
                    ),
                    timeout=4.0,
                )
            except (OSError, ConnectionError, asyncio.TimeoutError):
                retry = None
            if retry:
                stuns = retry
                self.stun_clients.setdefault(self.af, {})[if_index] = retry

        if not stuns:
            return None, None

        src_ip = self.src["ip"]
        dest_ip = self.dest["ip"]
        if src_ip and dest_ip and str(src_ip) == str(dest_ip):
            log("tcp_punch_pcap_v2: dest matches own bind IP ({0}); "
                "aborting".format(dest_ip))
            return None, None

        decider_ip = src_ip
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

        timestamp = self.sys_clock.time()
        puncher.set_timestamp(timestamp)
        p = puncher.params
        _, punch_time = compute_rendezvous(
            timestamp,
            window=p["window"],
            min_run_window=p["min_run_window"],
            max_error=p["max_clock_error"],
        )
        secondary_punch_time = punch_time + p["window"]
        print("[CLOCK-PCAPV2] my_now={0} punch_time={1} delta={2} "
              "window={3} max_clock_error={4}".format(
                  timestamp, punch_time, punch_time - timestamp,
                  p["window"], p["max_clock_error"],
              ), flush=True)
        puncher.set_punch_time(
            punch_time, secondary_punch_time=secondary_punch_time,
        )
        puncher.add_port_allocator(boundary_port_alloc)
        return puncher, stuns

    async def configure_puncher_process(self, puncher, stuns):
        self.punch_clients[self.plugin_id] = puncher
        self.nat_alloc = NATPredictAlloc(stuns)
        self.nat_alloc.set_nat_info(self.src["nat"], self.dest["nat"])
        self.nat_alloc.set_punch_mode(self.same_machine, self.dest["ip"])
        if self.plugin_id not in self.punch_proc:
            self.punch_proc[self.plugin_id] = asyncio.ensure_future(
                async_wrap_errors(self.delayed_start_punching_proc(
                    self.nic, puncher,
                )),
            )
        return puncher

    async def advance_punching_protocol(self, puncher, reply, punch_time):
        """Identical shape to tcp_punch.advance_punching_protocol."""
        tx_unix = int(self.sys_clock.time())
        clock_uncertainty = float(getattr(self.sys_clock, "uncertainty", 0.0))

        if self.nat_alloc.punch_mode == TCP_PUNCH_LAN:
            if reply is not None:
                return None
            msg = PunchMsg({
                "payload": {
                    "punch_mode": self.nat_alloc.punch_mode,
                    "mappings": [],
                    "ntp": punch_time,
                    "tx_unix": tx_unix,
                    "clock_uncertainty": clock_uncertainty,
                },
            })
            msg.meta.plugin_name = "tcp_punch"
            return msg

        recv_mappings = None
        if reply is not None:
            recv_mappings = [NATMapping(m) for m in reply.payload.mappings]
            if not recv_mappings:
                log("tcp_punch_pcap_v2: peer sent empty mappings; dropping")
                return None

        port_alloc, is_end = await self.nat_alloc.port_alloc(recv_mappings)
        puncher.port_allocs += port_alloc

        if is_end == 1:
            return None

        mappings = [m.to_json() for m in self.nat_alloc.send_mappings]
        msg = PunchMsg({
            "payload": {
                "punch_mode": self.nat_alloc.punch_mode,
                "mappings": mappings,
                "ntp": punch_time,
                "tx_unix": tx_unix,
                "clock_uncertainty": clock_uncertainty,
            },
        })
        msg.meta.plugin_name = "tcp_punch"
        return msg

    async def delayed_start_punching_proc(self, nic, puncher):
        """Wait coordinator delay then fire the pcap engine."""
        coordinator_delay = puncher.params.get("coordinator_delay", 0.5)
        print("[PUNCH-PCAPV2-DELAY] enter delay={0}s".format(
            coordinator_delay,
        ), flush=True)
        firewall_ports = []
        try:
            await asyncio.sleep(coordinator_delay)
            # Install per-OS firewall blocks on every predicted local
            # port BEFORE the punch fires. tcpip.sys / Linux kernel
            # must NOT see the SYN as "no socket listening" and emit
            # an RST; the pcap stack will own the handshake.
            local_ports = sorted(set(int(pa.src_port)
                                     for pa in puncher.port_allocs))
            firewall_ports = install_block_ports(local_ports)

            # Resolve pcap NIC name. On Unix it's the NIC's name; on
            # Windows it's the NPF device path. Same lookup the original
            # tcp_punch_pcap plugin's lookup_nic_pcap_name uses.
            nic_pcap_name = self.lookup_nic_pcap_name(puncher.src_ip)

            # Build an async sleep_until wrapper around the legacy
            # PunchClient.sleep_until (which time.sleep()'s).
            loop = asyncio.get_event_loop()

            async def sleep_until_async():
                await loop.run_in_executor(None, puncher.sleep_until)

            winner = await pcap_selector_punch_engine(
                nic_pcap_name=nic_pcap_name,
                port_allocs=puncher.port_allocs,
                src_ip=puncher.src_ip,
                dest_ip=puncher.dest_ip,
                f_sleep_until_async=sleep_until_async,
                params=puncher.params,
                loop=loop,
            )
            print("[PUNCH-PCAPV2-DELAY] engine returned {0}".format(
                "winner" if winner is not None else "None",
            ), flush=True)

            # Secondary-bucket fallback. If the primary missed and the
            # PunchClient carries a secondary_punch_time, retry the
            # same port_allocs (boundary_port_alloc already produced
            # union(B, B+1)) at the secondary rendezvous.
            if winner is None and puncher.secondary_punch_time:
                log("tcp_punch_pcap_v2: primary missed; firing secondary "
                    "at {0}".format(puncher.secondary_punch_time))
                puncher.punch_time = puncher.secondary_punch_time
                puncher.secondary_punch_time = 0
                winner = await pcap_selector_punch_engine(
                    nic_pcap_name=nic_pcap_name,
                    port_allocs=puncher.port_allocs,
                    src_ip=puncher.src_ip,
                    dest_ip=puncher.dest_ip,
                    f_sleep_until_async=sleep_until_async,
                    params=puncher.params,
                    loop=loop,
                )

            if not self.result.done():
                self.result.set_result(winner)
            elif winner is not None:
                try:
                    await winner.close()
                except Exception:
                    pass
        except asyncio.CancelledError:
            print("[PUNCH-PCAPV2-DELAY] CANCELLED", flush=True)
            raise
        except Exception as exc:
            print("[PUNCH-PCAPV2-DELAY] EXCEPTION {0}: {1}".format(
                type(exc).__name__, repr(exc),
            ), flush=True)
            raise
        finally:
            if firewall_ports:
                try:
                    remove_block_ports(firewall_ports)
                except Exception as exc:
                    log("tcp_punch_pcap_v2: remove_block_ports raised "
                        "{0}".format(exc))
            self.completed_pipe_ids.add(self.plugin_id)

    def lookup_nic_pcap_name(self, my_ip):
        """Map self.nic to the pcap interface name.

        Unix: NIC's name attribute IS the pcap name.
        Windows: walk pcap_findalldevs and match by IP.
        """
        nic = self.nic
        explicit = getattr(nic, "pcap_name", None)
        if explicit:
            return explicit
        if not sys.platform.startswith("win"):
            return getattr(nic, "name", None) or ""
        try:
            from aionetiface.net.pcap import get_backend
            factory = get_backend()
        except Exception:
            return ""
        for entry in factory.list_interfaces():
            if my_ip and my_ip in (entry.get("addresses") or ()):
                return entry["name"]
        return ""

    async def close(self):
        """Cancel any in-flight delayed-start task."""
        task = self.punch_proc.pop(self.plugin_id, None)
        self.punch_clients.pop(self.plugin_id, None)
        await cancel_task(task)
        if not self.result.done():
            self.result.cancel()
        self.completed_pipe_ids.add(self.plugin_id)


class PunchPcapV2Factory:
    """Mirror of PunchPluginFactory: shared STUN clients + per-session state.

    The v2 plugin doesn't need a ProcessPoolExecutor (pcap engine
    runs in the main loop), so factory state is just STUN clients,
    SysClock, and the per-plugin dicts.
    """

    def __init__(self, stun_clients, sys_clock=None,
                 punch_clients=None):
        self.stun_clients = stun_clients
        self.sys_clock = sys_clock or SysClock(None, 0.1)
        self.punch_clients = punch_clients if punch_clients is not None else {}
        self.punch_proc = {}
        self.completed_pipe_ids = set()

    @classmethod
    def create(cls, stun_clients, sys_clock):
        return cls(stun_clients, sys_clock)

    def build_plugin(self):
        plugin = PunchPcapV2Plugin()
        plugin.stun_clients = self.stun_clients
        plugin.sys_clock = self.sys_clock
        plugin.punch_clients = self.punch_clients
        plugin.punch_proc = self.punch_proc
        plugin.completed_pipe_ids = self.completed_pipe_ids
        return plugin

    async def close(self):
        # Nothing to shut down: no proc pool, no shared sockets.
        return None
