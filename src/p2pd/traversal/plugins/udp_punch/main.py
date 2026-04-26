"""Traversal plugin for UDP hole-punching with predictable NAT mappings.

Mirrors tcp_punch.PunchPlugin's protocol exchange (NAT prediction +
boundary-time rendezvous) but uses a UDP engine for the actual fire/
verify phase.  UDP requires no SYN-ACK so the engine returns its
result socket directly -- no process pool, no reverse-connect tunnel.

Like tcp_punch, this plugin opts out of LOOPBACK_BIND: the loopback
path has no NAT to traverse so port prediction does no useful work.
For symmetric NAT pairs, use the random_probe plugin instead --
udp_punch only handles cone NATs and predictable-symmetric NATs.
"""
from typing import Any, Dict, Optional, Tuple
import asyncio
import os

from aionetiface import (
    EXT_BIND, NIC_BIND, Pipe, SysClock, UDP, fstr, log, log_exception,
    rand_b,
)

from ....protocol.proto_msg import UdpPunchMsg
from ...traversal_plugin import TraversalPlugin
from ..tcp_punch.boundary_alloc import boundary_port_alloc
from ..tcp_punch.boundary_lib import FAST_PUNCH_PARAMS, compute_rendezvous
from ..tcp_punch.nat_predict import NATMapping
from ..tcp_punch.nat_predict_alloc import NATPredictAlloc
from ..tcp_punch.punch_client import PunchClient
from .udp_punch_defs import UDP_PUNCH_FRAME_LEN, UDP_PUNCH_MAGIC, UDP_PUNCH_NONCE_LEN
from .udp_punch_engine import drain_punch_residue, udp_punch_engine


class UdpPunchPlugin(TraversalPlugin):
    """Traversal plugin implementing UDP hole-punching via coordinated port prediction."""

    # Same exclusions as tcp_punch -- loopback has no NAT so prediction
    # does no useful work over it. Symmetric NAT goes to random_probe,
    # not here.
    SUPPORTED_ROUTE_TYPES = (NIC_BIND, EXT_BIND)

    async def run(self, reply: Optional[Any] = None) -> None:
        """Coordinate the punch exchange and fire the in-process UDP engine."""
        puncher = self.punch_clients.get(self.plugin_id)
        if puncher is None:
            puncher, stuns = await self.setup_puncher_client(reply)
            if puncher is None:
                log("UdpPunchPlugin: no STUN clients available; aborting punch.")
                return

            # Concurrent run() may have raced through; reuse the registered client.
            puncher = self.punch_clients.get(self.plugin_id) or puncher
            if self.plugin_id not in self.punch_clients:
                puncher = await self.configure_puncher_process(puncher, stuns)

        # Compute the next round of port predictions.
        outgoing_msg = await self.advance_punching_protocol(
            puncher, reply, puncher.punch_time
        )

        # None signals the exchange is complete; the in-process engine
        # task takes over from here.
        if outgoing_msg is None:
            return

        # The first message in a session carries the session nonce so the
        # peer knows what magic to look for in inbound probes. We attach
        # it on every outbound -- repeated copies cost nothing and let
        # late-arriving peers join.
        outgoing_msg.payload.mappings = [m.to_json() for m in self.nat_alloc.send_mappings]

        await self.send_signal_msg(outgoing_msg)

    async def setup_puncher_client(self, reply: Optional[Any]) -> Tuple[Optional[Any], Optional[Any]]:
        """Build a fresh PunchClient + decide on a session nonce for this attempt."""
        if_index = self.src_info["if_index"]
        stuns = self.stun_clients[self.af][if_index]
        if not stuns:
            return None, None

        dest_ip = self.dest_info["ip"]

        # Defensive: same-NIC self-target would loop the predictions
        # back through the local stack with no NAT involvement.
        try:
            src_nic_ip = self.src_info.get("nic")
        except AttributeError:
            src_nic_ip = None
        if src_nic_ip is not None:
            try:
                if str(src_nic_ip) == str(dest_ip):
                    log("UdpPunchPlugin: dest matches own NIC IP ({0}); aborting".format(dest_ip))
                    return None, None
            except (TypeError, ValueError):
                pass

        route = await self.nic.route(self.af).bind()
        if "fe80" == dest_ip[:4]:
            src_ip = str(route.link_locals[0])
        else:
            src_ip = route.nic()

        if self.route_type == NIC_BIND:
            decider_ip = src_ip
        else:
            decider_ip = route.ext()

        puncher = PunchClient(
            dest_ip,
            src_ip,
            decider_ip,
            self.nic.id,
            same_machine=self.same_machine,
            params=FAST_PUNCH_PARAMS,
        )

        # Session nonce: pulled from the peer's first message if we're
        # the responder, otherwise generated locally and sent on our
        # outgoing PunchMsg.payload.mappings (we tag it onto every msg
        # via this object so both sides converge to the same value).
        if reply is not None and getattr(reply.payload, "nonce", None):
            try:
                puncher.udp_nonce = bytes.fromhex(reply.payload.nonce)
            except (ValueError, TypeError):
                puncher.udp_nonce = rand_b(UDP_PUNCH_NONCE_LEN)
        else:
            puncher.udp_nonce = rand_b(UDP_PUNCH_NONCE_LEN)

        timestamp = self.sys_clock.time()
        puncher.set_timestamp(timestamp)
        p = puncher.params
        _, punch_time = compute_rendezvous(
            timestamp,
            window=p["window"],
            min_run_window=p["min_run_window"],
            max_error=p["max_clock_error"],
        )
        puncher.set_punch_time(punch_time)
        puncher.add_port_allocator(boundary_port_alloc)

        return puncher, stuns

    async def configure_puncher_process(self, puncher: Any, stuns: Any) -> Any:
        """Register the puncher and schedule the in-process punch engine."""
        self.punch_clients[self.plugin_id] = puncher

        self.nat_alloc = NATPredictAlloc(stuns)
        self.nat_alloc.set_nat_info(self.src_info["nat"], self.dest_info["nat"])
        self.nat_alloc.set_punch_mode(self.same_machine, self.dest_info["ip"])

        if self.plugin_id not in self.punch_proc:
            self.punch_proc[self.plugin_id] = asyncio.create_task(
                self.delayed_run_engine(puncher)
            )
        return puncher

    async def advance_punching_protocol(self, puncher: Any, reply: Optional[Any], punch_time: int) -> Optional[Any]:
        """Compute the next round of port predictions; return outgoing UdpPunchMsg or None when done."""
        recv_mappings = None
        if reply is not None:
            recv_mappings = [NATMapping(m) for m in reply.payload.mappings]
            assert recv_mappings

        port_alloc, is_end = await self.nat_alloc.port_alloc(recv_mappings)
        puncher.port_allocs += port_alloc

        if is_end == 1:
            return None

        mappings = [m.to_json() for m in self.nat_alloc.send_mappings]
        msg = UdpPunchMsg({
            "payload": {
                "punch_mode": self.nat_alloc.punch_mode,
                "mappings": mappings,
                "ntp": punch_time,
                "nonce": puncher.udp_nonce.hex(),
            },
        })
        msg.meta.plugin_name = "udp_punch"
        return msg

    async def delayed_run_engine(self, puncher: Any) -> None:
        """Wait for coordinator delay, run the UDP engine in an executor, wrap winner in Pipe."""
        coordinator_delay = puncher.params.get("coordinator_delay", 2.0)
        try:
            await asyncio.sleep(coordinator_delay)

            loop = asyncio.get_event_loop()
            # The engine is pure-sync (select-based) so run it in a
            # thread; concurrent UDP sprays on multiple plugins won't
            # collide (each has its own bound sockets).
            af = puncher.af
            nic_id = puncher.nic_id
            port_allocs = list(puncher.port_allocs)
            src_ip = puncher.src_ip
            dest_ip = puncher.dest_ip
            same_machine = puncher.same_machine
            params = puncher.params
            nonce = puncher.udp_nonce
            f_sleep_until = puncher.sleep_until

            def run_sync():
                return udp_punch_engine(
                    af=af,
                    nic_id=nic_id,
                    port_allocs=port_allocs,
                    src_ip=src_ip,
                    dest_ip=dest_ip,
                    f_sleep_until=f_sleep_until,
                    nonce=nonce,
                    same_machine=same_machine,
                    params=params,
                )

            result = await loop.run_in_executor(None, run_sync)
            if result is None:
                if not self.result.done():
                    self.result.set_result(None)
                return

            winner_sock, peer_addr = result

            # Drain queued PROBE/CONFIRM frames before the Pipe wrap;
            # the peer's spray keeps arriving for hundreds of ms past
            # convergence and those frames would otherwise be the
            # first thing pipe.recv() returns to the application.
            drain_punch_residue(winner_sock, puncher.udp_nonce)

            # Wrap the winning socket in a Pipe so the caller has the
            # same interface as the other plugins return. UDP Pipe
            # accepts an existing sock=... and uses it directly.
            try:
                route = self.nic.route(self.af)
                pipe = await Pipe(
                    UDP, dest=peer_addr, route=route, sock=winner_sock,
                ).connect()
            except (OSError, ConnectionError, asyncio.TimeoutError):
                log_exception()
                pipe = None
                try:
                    winner_sock.close()
                except OSError:
                    pass

            if pipe is not None:
                # Late-arriving PROBE/CONFIRM frames also need to be
                # filtered at the pipe-stream layer: PipeEvents queues
                # data via stream.add_msg before node_protocol fires,
                # so without this hook pipe.recv(SUB_ALL) returns
                # frame bytes ahead of the actual application reply.
                # Mirrors random_probe's stream.add_msg monkey-patch.
                try:
                    stream = pipe.pipe_events.stream
                    original_add_msg = stream.add_msg
                    nonce_bytes = puncher.udp_nonce

                    def filtered_add_msg(data, client_tup):
                        if (
                            len(data) == UDP_PUNCH_FRAME_LEN
                            and bytes(data[:4]) == UDP_PUNCH_MAGIC
                            and bytes(data[5:5 + len(nonce_bytes)]) == nonce_bytes
                        ):
                            return
                        return original_add_msg(data, client_tup)

                    stream.add_msg = filtered_add_msg
                except (AttributeError, TypeError):
                    pass

            if not self.result.done():
                self.result.set_result(pipe)
        finally:
            self.punch_proc.pop(self.plugin_id, None)
            self.punch_clients.pop(self.plugin_id, None)

    async def close(self) -> None:
        """Cancel any in-flight engine task and clear the per-session state."""
        task = self.punch_proc.pop(self.plugin_id, None)
        self.punch_clients.pop(self.plugin_id, None)
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

        if not self.result.done():
            self.result.cancel()


class UdpPunchPluginFactory:
    """Creates UdpPunchPlugin instances sharing STUN clients + per-plugin state."""

    def __init__(
        self,
        stun_clients: Any,
        sys_clock: Optional[Any] = None,
        punch_clients: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.stun_clients = stun_clients
        self.sys_clock = sys_clock or SysClock(None, 0.1)
        self.punch_clients = punch_clients if punch_clients is not None else {}
        self.punch_proc = {}

    @classmethod
    async def create(cls, stun_clients: Any, sys_clock: Any) -> "UdpPunchPluginFactory":
        """Async factory; UDP punch needs no process pool so this is a thin wrapper."""
        return cls(stun_clients, sys_clock)

    def build_plugin(self) -> UdpPunchPlugin:
        """Create a fresh UdpPunchPlugin wired to this factory's shared state."""
        plugin = UdpPunchPlugin()
        plugin.stun_clients = self.stun_clients
        plugin.sys_clock = self.sys_clock
        plugin.punch_clients = self.punch_clients
        plugin.punch_proc = self.punch_proc
        return plugin

    async def close(self) -> None:
        """No-op; UDP punch holds no process pool."""
        return None


PLUGIN_CONF = {"timeout": 30}


async def setup_plugin(node):
    """Create the udp_punch factory; returns None if punching is disabled in node.conf."""
    if not node.conf.get("enable_punching", True):
        return None
    factory = await UdpPunchPluginFactory.create(node.stun_clients, node.sys_clock)
    return factory
