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
import socket as _socket

from aionetiface import (
    EXT_BIND, NIC_BIND, Pipe, SysClock, UDP, fstr, log, log_exception,
    rand_b,
)
from aionetiface.net.selector_proxy import selector_proxy

from ....protocol.proto_defs import P2P_PUNCH
from ...traversal_plugin import TraversalPlugin
from ..tcp_punch.boundary_alloc import boundary_port_alloc
from ..tcp_punch.boundary_lib import FAST_PUNCH_PARAMS, compute_rendezvous
from ..tcp_punch.nat_predict import NATMapping
from ..tcp_punch.nat_predict_alloc import NATPredictAlloc
from ..tcp_punch.punch_client import PunchClient
from ..tcp_punch.punch_defs import TCP_PUNCH_LAN
from .proto import UdpPunchMsg
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
        # send_mappings is only populated after nat_alloc.port_alloc()
        # runs; the TCP_PUNCH_LAN short-circuit in
        # advance_punching_protocol returns before that call so the
        # attribute may not exist. Default to whatever the LAN path
        # already put on payload.mappings (empty list).
        send_mappings = getattr(self.nat_alloc, "send_mappings", None)
        if send_mappings:
            outgoing_msg.payload.mappings = [
                m.to_json() for m in send_mappings
            ]

        await self.send_signal_msg(outgoing_msg)

    async def setup_puncher_client(self, reply: Optional[Any]) -> Tuple[Optional[Any], Optional[Any]]:
        """Build a fresh PunchClient + decide on a session nonce for this attempt."""
        if_index = self.src_info["if_index"]
        # Safe two-level lookup; same rationale as tcp_punch's
        # setup_puncher_client: hosts without working v6 STUN
        # (XP / Vista) never populate the inner dict for
        # (af=AF_INET6, if_index), and bare indexing raises KeyError
        # before the "no STUN clients loaded" guard runs.
        stuns = self.stun_clients.get(self.af, {}).get(if_index, [])
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
            # Bake the AF-correct scope_id into both the dest and src
            # link-local IPs so Windows sendto / connect_ex reach the
            # right interface. Without this the engine sprays into the
            # OS-default NIC and the peer never sees the probes.
            # Mirrors tcp_punch's setup_puncher_client (commits 10f4977
            # + 87148ae). XP keeps separate v4/v6 ifindex spaces, so
            # use get_nic_id(af) instead of nic.id.
            from aionetiface.net.bind.bind_utils import ip6_patch_bind_ip
            v6_scope = self.nic.get_nic_id(self.af)
            dest_ip = ip6_patch_bind_ip(dest_ip.split("%", 1)[0], v6_scope)
            src_ip = ip6_patch_bind_ip(src_ip.split("%", 1)[0], v6_scope)
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
            self.nic.get_nic_id(self.af),
            same_machine=self.same_machine,
            params=FAST_PUNCH_PARAMS,
        )
        # Attach the bound route so delayed_run_engine can forward it
        # to bind_punch_sockets for NIC pinning. PunchClient itself is
        # tcp_punch's API and stays unaware of route -- udp_punch
        # alone needs this for multi-NIC correctness.
        puncher.route = route

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
        # For LAN, STUN is useless (returns each side's own port).
        # boundary_port_alloc in delayed_run_engine handles port
        # alignment between peers via NTP-aligned bucket. Send one
        # empty-mappings UdpPunchMsg to trigger the recipient; return
        # None on any reply. Mirrors tcp_punch's LAN short-circuit
        # (commit cb7a765). Nonce stays in payload.nonce so the
        # responder still sees it without the mappings round-trip.
        if self.nat_alloc.punch_mode == TCP_PUNCH_LAN:
            if reply is not None:
                return None
            msg = UdpPunchMsg({
                "payload": {
                    "punch_mode": self.nat_alloc.punch_mode,
                    "mappings": [],
                    "ntp": punch_time,
                    "nonce": puncher.udp_nonce.hex(),
                },
            })
            msg.meta.plugin_name = "udp_punch"
            return msg

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
        """Wait for coordinator delay, set up bridge, dispatch worker that runs engine + bridge."""
        coordinator_delay = puncher.params.get("coordinator_delay", 2.0)
        try:
            await asyncio.sleep(coordinator_delay)

            # ---- Bridge setup (main side) ----
            #
            # Architecture (mirrors tcp_punch's reverse_server pattern,
            # adapted for UDP's connectionless model):
            #
            #   worker thread             |     main asyncio loop
            #   ------------------------- |     ----------------------
            #   punched_sock (peer-       |     listener_sock (Pipe)
            #     facing UDP, bound to    |       on (loopback, 0)
            #     puncher.src_ip:port)    |
            #          ^                  |          ^
            #          | selector_proxy   |          | datagrams via
            #          | bridge (DGRAM)   |          | asyncio loop
            #          v                  |          v
            #   worker_sock (loopback,    | --->  recvfrom -> msg_cbs
            #     UDP-connected to        | <---  pipe.send -> sendto
            #     listener_sock)          |
            #
            # Why both sockets are pre-built in main:
            # - Pre-creating both sockets lets us know the worker's
            #   bridge addr BEFORE the worker starts. Without this,
            #   the connector side's pipe.send(ECHO) -- which fires
            #   immediately after plugin.result resolves -- would
            #   have no dest_tup until the first inbound datagram
            #   from the worker, which never comes if the connector
            #   is the one with data to send first.
            # - The wrapped Pipe is built on listener_sock which has
            #   never been touched by select() in a worker thread,
            #   so asyncio's selector sees a clean fd. Avoids the
            #   "deaf wrap" failure that the rebind workaround was
            #   trying (and only partially succeeding) to dodge.
            # - Pre-populating msg_cbs on the wrapped Pipe before
            #   dispatching the worker covers the wireup race the
            #   same way tcp_punch's reverse_server does.

            if puncher.af == 2:
                loopback_host = "127.0.0.1"
                family = _socket.AF_INET
            else:
                loopback_host = "::1"
                family = _socket.AF_INET6

            try:
                listener_sock = _socket.socket(family, _socket.SOCK_DGRAM)
                listener_sock.setsockopt(
                    _socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1,
                )
                listener_sock.setblocking(False)
                listener_sock.bind((loopback_host, 0))

                worker_sock = _socket.socket(family, _socket.SOCK_DGRAM)
                worker_sock.setsockopt(
                    _socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1,
                )
                worker_sock.setblocking(False)
                worker_sock.bind((loopback_host, 0))

                # getsockname() returns a 2-tuple for v4 and a 4-tuple
                # for v6 ((host, port, flowinfo, scope_id)). The Pipe
                # constructor's resolve_dest does `ip, port = dest`
                # which blows up on the v6 4-tuple. Keep the full
                # tuple for socket.connect (v6 form is required there)
                # but pass a flat (ip, port) to Pipe.
                listener_addr = listener_sock.getsockname()
                worker_addr = worker_sock.getsockname()
                worker_addr_for_pipe = (worker_addr[0], worker_addr[1])
                # UDP-connect both ends so recv/send default to the
                # known peer and the kernel filters incoming.
                listener_sock.connect(worker_addr)
                worker_sock.connect(listener_addr)
            except OSError as exc:
                log(fstr(
                    "udp_punch.delayed_run_engine: bridge setup failed: {0}",
                    (repr(exc),),
                ))
                log_exception()
                if not self.result.done():
                    self.result.set_result(None)
                return

            log(fstr(
                "udp_punch.delayed_run_engine: bridge listener={0} worker={1}",
                (listener_addr, worker_addr),
            ))

            # Wrap listener_sock as a UDP Pipe -- main owns it from
            # creation, asyncio sees a fresh fd, dest_tup is set to
            # worker_addr so pipe.send works immediately.
            try:
                route = self.nic.route(self.af)
                pipe = await Pipe(
                    UDP, dest=worker_addr_for_pipe,
                    route=route, sock=listener_sock,
                ).connect()
            except (OSError, ConnectionError, asyncio.TimeoutError):
                log_exception()
                pipe = None
                for s in (listener_sock, worker_sock):
                    try:
                        s.close()
                    except OSError:
                        pass

            if pipe is None:
                log("udp_punch.delayed_run_engine: Pipe.connect() returned None")
                if not self.result.done():
                    self.result.set_result(None)
                return

            try:
                wrapped_addr = pipe.sock.getsockname()
            except (OSError, AttributeError):
                wrapped_addr = None
            log(fstr(
                "udp_punch.delayed_run_engine: wrapped Pipe local={0} dest={1}",
                (wrapped_addr, worker_addr),
            ))

            # Pre-populate msg_cbs with the node-level dispatcher
            # BEFORE dispatching the worker. Mirrors the wireup-race
            # fix in tcp_punch's start_punching_process.
            node_msg_cb = getattr(self, "node_msg_cb", None)
            if (
                node_msg_cb is not None
                and getattr(pipe, "pipe_events", None) is not None
            ):
                pe = pipe.pipe_events
                before = len(pe.msg_cbs)
                pe.msg_cbs.add(node_msg_cb)
                if len(pe.msg_cbs) != before:
                    log(fstr(
                        "udp_punch.delayed_run_engine: pre-populated "
                        "pipe.msg_cbs (count={0})",
                        (len(pe.msg_cbs),),
                    ))

            # Snapshot puncher state for the worker thread.
            af = puncher.af
            nic_id = puncher.nic_id
            port_allocs = list(puncher.port_allocs)
            src_ip = puncher.src_ip
            dest_ip = puncher.dest_ip
            same_machine = puncher.same_machine
            params = puncher.params
            nonce = puncher.udp_nonce
            f_sleep_until = puncher.sleep_until
            puncher_route = puncher.route
            stop_reader = self.stop_reader

            loop = asyncio.get_event_loop()
            # convergence is resolved by the worker via call_soon_threadsafe
            # the moment the engine returns a winner and selector_proxy is
            # ready to read worker_sock. Until that happens, ECHO bytes the
            # demo writes to listener_sock just queue in worker_sock's recv
            # buffer with nobody draining them. Resolving plugin.result
            # before the bridge is alive caused the matrix to hit
            # echo-recv timeout 100% of the time -- demo's 1 s pre-sleep
            # + 4 s recv timeout < spray (3 s) + listen (3 s) = 6 s engine
            # window, so the demo always gave up before selector_proxy
            # started forwarding. Mirrors tcp_punch's start_punching_process
            # which only returns the pipe after the worker has converged.
            convergence = asyncio.Future()

            def signal_convergence(success):
                if not convergence.done():
                    convergence.set_result(success)

            def punch_and_bridge():
                """Worker: run UDP engine, signal main, then bridge."""
                try:
                    result = udp_punch_engine(
                        af=af,
                        nic_id=nic_id,
                        port_allocs=port_allocs,
                        src_ip=src_ip,
                        dest_ip=dest_ip,
                        f_sleep_until=f_sleep_until,
                        nonce=nonce,
                        same_machine=same_machine,
                        params=params,
                        stop_reader=stop_reader,
                        route=puncher_route,
                    )
                except Exception:  # pylint: disable=broad-except
                    log_exception()
                    loop.call_soon_threadsafe(signal_convergence, False)
                    return
                if result is None:
                    log("[UDP-WORKER] engine returned None")
                    loop.call_soon_threadsafe(signal_convergence, False)
                    return

                punched_sock, peer_addr = result
                try:
                    local_addr = punched_sock.getsockname()
                except OSError:
                    local_addr = None
                log(fstr(
                    "[UDP-WORKER] engine WINNER local={0} peer={1} fd={2}",
                    (local_addr, peer_addr, punched_sock.fileno()),
                ))

                # Drain residual PROBE/CONFIRM still buffered on the
                # punched sock from the spray window; otherwise the
                # bridge would forward them to main where the stream
                # filter would have to drop each.
                drained = drain_punch_residue(punched_sock, nonce)
                log(fstr(
                    "[UDP-WORKER] drained {0} residual frames",
                    (drained,),
                ))

                # UDP-connect punched_sock to peer so recv() filters
                # to the peer and send() targets the peer.
                try:
                    punched_sock.connect(peer_addr)
                except OSError as exc:
                    log(fstr(
                        "[UDP-WORKER] punched_sock.connect failed: {0}",
                        (repr(exc),),
                    ))
                    log_exception()
                    try:
                        punched_sock.close()
                    except OSError:
                        pass
                    loop.call_soon_threadsafe(signal_convergence, False)
                    return

                # Bridge is wired; let main resolve plugin.result so
                # the demo can start sending ECHO and have it actually
                # land on punched_sock.
                log(fstr(
                    "[UDP-WORKER] bridging punched <-> worker_sock {0}",
                    (worker_addr,),
                ))
                loop.call_soon_threadsafe(signal_convergence, True)

                try:
                    selector_proxy(
                        punched_sock,
                        listener_addr,
                        stop_reader,
                        sock_proto=_socket.SOCK_DGRAM,
                        socket_r=worker_sock,
                    )
                except Exception:  # pylint: disable=broad-except
                    log_exception()
                log("[UDP-WORKER] selector_proxy returned; worker exiting")

            worker_fut = loop.run_in_executor(None, punch_and_bridge)

            def worker_done(fut):
                try:
                    exc = fut.exception()
                except (asyncio.CancelledError, Exception):  # pylint: disable=broad-except
                    exc = None
                if exc is not None:
                    log(fstr(
                        "[UDP-WORKER] future raised {0}: {1}",
                        (type(exc).__name__, repr(exc)),
                    ))
                else:
                    log("[UDP-WORKER] future completed cleanly")
                # Belt-and-braces: if the worker crashed before
                # signalling convergence, unblock main so plugin.result
                # gets a None instead of hanging on plugin timeout.
                if not convergence.done():
                    convergence.set_result(False)
            worker_fut.add_done_callback(worker_done)

            if pipe is not None:
                # Late-arriving PROBE/CONFIRM frames also need to be
                # filtered at the pipe-stream layer: PipeEvents queues
                # data via stream.add_msg before node_protocol fires,
                # so without this hook pipe.recv(SUB_ALL) returns
                # frame bytes ahead of the actual application reply.
                # Mirrors random_probe's stream.add_msg monkey-patch.
                drop_count = [0]
                pass_count = [0]
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
                            drop_count[0] += 1
                            if drop_count[0] <= 3 or drop_count[0] % 50 == 0:
                                log(fstr(
                                    "udp_punch.filter: dropped punch frame #{0} from {1}",
                                    (drop_count[0], client_tup),
                                ))
                            return
                        pass_count[0] += 1
                        if pass_count[0] <= 3 or pass_count[0] % 50 == 0:
                            preview = bytes(data[:8]) if len(data) >= 8 else bytes(data)
                            log(fstr(
                                "udp_punch.filter: PASSING msg #{0} from {1} len={2} preview={3}",
                                (pass_count[0], client_tup, len(data), repr(preview)),
                            ))
                        return original_add_msg(data, client_tup)

                    stream.add_msg = filtered_add_msg
                    log("udp_punch.delayed_run_engine: stream filter installed")
                except (AttributeError, TypeError) as exc:
                    log(fstr(
                        "udp_punch.delayed_run_engine: filter install FAILED: {0}",
                        (repr(exc),),
                    ))

            # Block until the worker either converges (engine winner +
            # selector_proxy ready) or fails. The ceiling has to cover
            # the FULL pre-spray sleep_until wait (up to ~max_sleep
            # seconds while we wait for the next NTP rendezvous bucket)
            # plus spray + listen + a small slop for residue drain and
            # connect. Without that the wait fires before sleep_until
            # even returns and every pair records as no-convergence.
            engine_ceiling = (
                params.get("max_sleep", 65)
                + params.get("connect_timeout", 3.0)
                + params.get("monitor_timeout", 3.0)
                + 5.0
            )
            try:
                converged = await asyncio.wait_for(
                    convergence, timeout=engine_ceiling,
                )
            except asyncio.TimeoutError:
                log(fstr(
                    "udp_punch.delayed_run_engine: convergence wait timed "
                    "out after {0}s; treating as no-convergence",
                    (engine_ceiling,),
                ))
                converged = False

            log(fstr(
                "udp_punch.delayed_run_engine: convergence={0}",
                (converged,),
            ))

            if not self.result.done():
                self.result.set_result(pipe if converged else None)
        except Exception:  # pylint: disable=broad-except
            log_exception()
            if not self.result.done():
                self.result.set_result(None)
        # NOTE: do NOT pop punch_proc / punch_clients here -- not on the
        # success path and not on the exception path. The asyncio task
        # ends as soon as set_result fires, but the executor worker keeps
        # running for ~9 s of spray + listen plus the lifetime of the
        # bridge. If the peer's next signal arrives during that window
        # and run() is re-entered, popped state forces a fresh
        # setup_puncher_client + new engine task whose bind_punch_sockets
        # collides on the same predicted ports the first worker still
        # holds (Windows EADDRINUSE 10048). close() is the only place
        # that pops; cleanup semantics will be revisited in a dedicated
        # session.

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


# Process-level registry keyed by (nic_id, primary_route_ip, af).
# Two p2pd Nodes binding udp_punch sockets on the same (NIC, source
# IP, address family) tuple collide: both compute identical time-
# based port predictions via boundary_port_alloc, both try to bind
# those ports on the same source IP, the second bind hits
# EADDRINUSE, and (per our silent-skip-on-bind-failure path) the
# engine quietly proceeds with fewer sockets. The resulting failure
# looks identical to a NAT-prediction miss but is actually a self-
# collision.
#
# Different IPs on the same NIC don't collide (different bind
# tuples), and different AFs don't collide (separate v4/v6 socket
# tables in the kernel) -- so the key is the full tuple, not just
# the nic_id.
PUNCH_NIC_OWNERS = {}


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
        self.nic_ids_owned = []
        # Populated by setup_plugin with (nic_id, ip, af) tuples this
        # factory wants to claim. Actual claim happens lazily on
        # first build_plugin so registration never fails on collision.
        self.pending_claims = []

    @classmethod
    async def create(cls, stun_clients: Any, sys_clock: Any) -> "UdpPunchPluginFactory":
        """Async factory; UDP punch needs no process pool so this is a thin wrapper."""
        return cls(stun_clients, sys_clock)

    def claim_nics(self, claims: Any) -> None:
        """Register this factory as the udp_punch owner for each (nic_id, ip, af) tuple; raise ValueError on collision."""
        for key in claims:
            if key in PUNCH_NIC_OWNERS:
                nic_id, ip_str, af = key
                raise ValueError(
                    "udp_punch is already active on (nic={0!r}, ip={1!r}, "
                    "af={2}) in this process. Two p2pd Nodes cannot run "
                    "udp_punch with the same source IP and address family "
                    "on the same NIC -- their port-prediction allocations "
                    "would collide on bind(). Run the second Node on a "
                    "different NIC, a different IP on this NIC, or in a "
                    "separate process.".format(nic_id, ip_str, af)
                )
            PUNCH_NIC_OWNERS[key] = self
            self.nic_ids_owned.append(key)

    def build_plugin(self) -> UdpPunchPlugin:
        """Create a fresh UdpPunchPlugin wired to this factory's shared state."""
        # Claim the (nic, ip, af) tuples lazily on first plugin
        # build. Raises ValueError if another factory in this process
        # already owns one of them -- caller (traversal manager) can
        # decide to skip / log / propagate. After the first claim
        # succeeds, pending_claims is cleared so re-builds don't
        # re-raise spuriously.
        if self.pending_claims:
            claims = self.pending_claims
            self.pending_claims = []
            self.claim_nics(claims)
        plugin = UdpPunchPlugin()
        plugin.stun_clients = self.stun_clients
        plugin.sys_clock = self.sys_clock
        plugin.punch_clients = self.punch_clients
        plugin.punch_proc = self.punch_proc
        return plugin

    async def close(self) -> None:
        """Release the NIC ownership claims so a fresh Node can re-create the factory."""
        for nic_id in self.nic_ids_owned:
            if PUNCH_NIC_OWNERS.get(nic_id) is self:
                del PUNCH_NIC_OWNERS[nic_id]
        self.nic_ids_owned = []


PLUGIN_CONF = {"timeout": 150}

PROTO_MESSAGES = (
    (UdpPunchMsg, P2P_PUNCH, 20),
)


async def setup_plugin(node):
    """Create the udp_punch factory; returns None if punching is disabled in node.conf."""
    if not node.conf.get("enable_punching", True):
        return None
    factory = await UdpPunchPluginFactory.create(node.stun_clients, node.sys_clock)
    # Stash the (nic_id, primary_ip, af) claims on the factory so the
    # first plugin run can claim them at engine-start time. Doing the
    # claim eagerly here would raise ValueError on collision, which
    # plugin_loader's broad except swallows -- udp_punch then silently
    # drops out of plugin_loaders and breaks tests that assert it
    # registered. Late-claim keeps registration unconditional and
    # surfaces collisions only when an actual punch attempt would
    # have been doomed anyway.
    claims = []
    for nic in node.ifs:
        nic_id = getattr(nic, "id", None)
        if not nic_id:
            continue
        for af in nic.supported():
            try:
                primary_ip = nic.nic(af)
            except (ValueError, LookupError, AttributeError):
                primary_ip = None
            if primary_ip:
                claims.append((nic_id, str(primary_ip), af))
    factory.pending_claims = claims
    return factory
