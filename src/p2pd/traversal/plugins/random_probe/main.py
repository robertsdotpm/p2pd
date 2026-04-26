"""Random-probe traversal plugin (Tailscale-style symmetric NAT traversal).

Designed for the (full-cone, symmetric) NAT pair.  The cone side
fires N UDP probes at random destination ports on the symmetric
peer's external IP; the symmetric side fires one probe from each
of N source-port-distinct sockets at the cone peer's known
(ext_ip, ext_port).  Birthday-paradox collision: with N=256 each,
~63% of attempts produce a 4-tuple that bridges both NATs.

The plugin uses the punch plugin's boundary algorithm purely for
*timing* -- both sides synchronise the moment they start firing so
the burst arrives within a NAT-mapping lifetime of itself.  The
transport is UDP-only because TCP simultaneous open is too fragile
for random-probe; see the design note at the bottom of this file.
"""

import asyncio
from typing import Any, Dict, List, Optional, Tuple

from aionetiface import (
    EXT_BIND,
    Pipe,
    SysClock,
    UDP,
    log,
    rand_b,
    to_s,
)
from aionetiface.nic.nat.nat_defs import SYMMETRIC_NAT

from ....protocol.proto_msg import RandomProbeMsg
from ...traversal_plugin import TraversalPlugin
from ..punch.boundary_lib import FAST_PUNCH_PARAMS, compute_rendezvous

from .random_probe_defs import DEFAULT_PROBE_COUNT, PROBE_LISTEN_TIMEOUT
from .random_probe_lib import (
    drain_probe_residue,
    make_udp_socket,
    run_non_sym_side,
    run_symmetric_side,
    stun_discover_mapping,
    wait_until,
)


def is_symmetric_nat(nat_info: Dict[str, Any]) -> bool:
    """
    True iff *nat_info* describes a symmetric NAT.

    The random-probe algorithm only cares about this single bit:
    is the peer's external port predictable per outbound flow?
    Symmetric NATs randomise it (the case the algorithm is
    designed to fix); everything else -- open internet (no NAT),
    full cone, restricted, port-restricted -- preserves enough
    structure that the peer can play the "fixed-port" role and
    publish a single (ip, port) the symmetric peer can aim at.

    A missing / empty nat_info is treated as non-symmetric: when
    the classifier didn't run (or hasn't finished), assume the
    permissive case so the algorithm gets to try.

    All non-symmetric callers in the plugin use ``not is_symmetric_nat()``
    directly; we don't expose a positively-worded counterpart
    because every potential name ("is_cone_nat",
    "is_predictable_nat") would be misleading -- the set is
    "everything except symmetric", not any specific NAT shape.
    """
    if not nat_info:
        return False
    return nat_info.get("type") == SYMMETRIC_NAT


class RandomProbePlugin(TraversalPlugin):
    """Tailscale-style random UDP probe rendezvous for one (cone, sym) pair.

    The pair must be (one cone-NAT side, one symmetric-NAT side).
    auto_combos is responsible for not generating combos that don't
    fit -- we still defensively bail in run() on malformed pairs.

    Only EXT_BIND is meaningful: random-probe is exactly the path
    you take when neither side can be reached on the LAN and direct
    public-IP punching has failed.
    """

    SUPPORTED_ROUTE_TYPES = (EXT_BIND,)

    async def run(self, reply: Optional[RandomProbeMsg] = None) -> None:
        """Drive the random-probe rendezvous from initiator or responder side."""
        # When user-driven (demo / explicit node.connect), route_type
        # may be NIC_BIND or LOOPBACK_BIND -- random_probe is an
        # EXT-only algorithm by design.  Bail loudly with a
        # ValueError so the demo prints something actionable rather
        # than a generic "Connection failed".
        if self.route_type is not None and self.route_type != EXT_BIND:
            self.set_failed_result()
            raise ValueError(
                "random_probe is for the WAN path only "
                "(needs both peers' external IP).  Pick (e)xternal, "
                "not LAN."
            )

        my_nat = self.src_info.get("nat") or {}
        peer_nat = self.dest_info.get("nat") or {}

        # Pick the addresses each side will fire probes at /from.
        # When the peer is on the same physical machine (machine_id
        # match) we use the NIC IPs -- the kernel delivers locally
        # via lo when the dst IP is bound on this host, which gives
        # a clean local 4-tuple without any router / NAT in the path.
        # Cross-machine: use ext IPs (the algorithm's normal mode).
        if self.same_machine:
            self.my_addr_ip = str(self.src_info.get("nic") or self.src_info.get("ext") or "")
            self.peer_addr_ip = str(self.dest_info.get("nic") or self.dest_info.get("ext") or "")
        else:
            self.my_addr_ip = str(self.src_info.get("ext") or "")
            self.peer_addr_ip = str(self.dest_info.get("ext") or "")

        # Role assignment by NAT restrictiveness, then by IP:
        #   1. Whichever side has the *higher* NAT type number plays
        #      "sym" -- nat_defs.py orders types from least to most
        #      restrictive (OPEN_INTERNET=1, FULL_CONE=3, RESTRICT=4,
        #      RESTRICT_PORT=5, SYMMETRIC=6, BLOCKED=7).  The more
        #      restrictive peer is the one that benefits from the
        #      256-sockets-burst pattern, since its outbound is the
        #      one that's hardest for the other side to predict.
        #   2. On a tie (same NAT type number, both ends of the link
        #      classified the same way), fall back to sorted IP --
        #      the side with the lexicographically smaller addr_ip
        #      plays "non_sym", the other plays "sym".  Both peers
        #      see the same pair of strings, so they always pick
        #      opposite roles.
        my_nat_n = int(my_nat.get("type") or 0)
        peer_nat_n = int(peer_nat.get("type") or 0)
        if my_nat_n > peer_nat_n:
            my_role = "sym"
        elif my_nat_n < peer_nat_n:
            my_role = "non_sym"
        else:
            # Tie-breaker on missing / equal addr: fall back to who
            # initiated (initiator = non_sym, responder = sym).
            if (
                self.my_addr_ip == self.peer_addr_ip
                or not self.my_addr_ip
                or not self.peer_addr_ip
            ):
                my_role = "non_sym" if reply is None else "sym"
            elif self.my_addr_ip < self.peer_addr_ip:
                my_role = "non_sym"
            else:
                my_role = "sym"

        if reply is None:
            # Initiator: pick a session nonce + rendezvous time and
            # send a RandomProbeMsg out.  Stash both on self so we
            # can match them when the peer's reply arrives.
            self.session_nonce = rand_b(16)
            self.session_role = my_role
            # NTP-aligned timestamp via SysClock.  Old VMs / boxes
            # without time-sync drift far enough that plain
            # time.time() blows the FAST_PUNCH_PARAMS.max_clock_error
            # (2 s) budget; SysClock samples a quorum of NTP servers
            # so both peers agree on the same Unix second within
            # the allowed error.
            timestamp = self.sys_clock.time()
            p = FAST_PUNCH_PARAMS
            _, punch_time = compute_rendezvous(
                timestamp,
                window=p["window"],
                min_run_window=p["min_run_window"],
                max_error=p["max_clock_error"],
            )
            self.punch_time = punch_time

            # If we're the non-sym side, pre-bind our UDP socket
            # right now so the port it ends up on can travel to the
            # peer in the message we're about to send.  Without
            # this, known_port = 0 and the symmetric side fires its
            # 256 probes at port 0 -- guaranteed no convergence.
            if my_role == "non_sym":
                await self.prebind_non_sym_sock()

            outgoing = self.build_msg(my_role, punch_time, to_s(self.session_nonce.hex()))
            outgoing.meta.plugin_name = "random_probe"
            await self.send_signal_msg(outgoing)
            return

        # Responder: extract peer's params, lock our role, fire.
        peer_role = reply.payload.role
        if peer_role == my_role:
            log(
                "RandomProbePlugin: peer claimed role={0} but I'm also "
                "{0}; aborting".format(peer_role)
            )
            return

        nonce = bytes.fromhex(reply.payload.magic)
        if len(nonce) != 16:
            log("RandomProbePlugin: bad nonce length in peer reply")
            return

        # Trust the peer's advertised addr if it's a usable string;
        # otherwise fall back to whatever we computed locally for
        # peer_addr_ip (NIC if same_machine, ext otherwise).  This
        # matters because the responder side may have computed its
        # own ext from a fresher set of fields than the initiator
        # parsed out of the on-wire addr_bytes.
        peer_addr_ip = reply.payload.ext_ip or self.peer_addr_ip
        peer_known_port = reply.payload.known_port
        probe_count = reply.payload.probe_count or DEFAULT_PROBE_COUNT
        punch_time = reply.payload.punch_time

        # If we're the responder we still owe the peer a reply with
        # our own external IP / known port.  Send it immediately so
        # they have what they need before the rendezvous fires.
        if not getattr(self, "session_nonce", None):
            self.session_nonce = nonce
            self.session_role = my_role
            self.punch_time = punch_time
            # Same pre-bind requirement as the initiator path: the
            # non-sym side has to commit to a port BEFORE building
            # the response, otherwise the peer fires at port 0.
            if my_role == "non_sym":
                await self.prebind_non_sym_sock()
            our_msg = self.build_msg(my_role, punch_time, reply.payload.magic)
            our_msg.meta.plugin_name = "random_probe"
            await self.send_signal_msg(our_msg)

        # Synchronise to the rendezvous time then fire.
        await wait_until(punch_time, max_sleep=p_or_default("max_sleep"))

        try:
            route = await self.nic.route(self.af).bind()
        except (OSError, ValueError):
            log("RandomProbePlugin: route bind failed; aborting")
            if not self.result.done():
                self.result.set_result(None)
            return
        bind_ip = str(route.nic())

        if my_role == "non_sym":
            # Reuse the socket we pre-bound before sending the
            # signal message.  Falling back to a fresh bind would
            # land on a different port than the one we advertised,
            # and the symmetric peer would fire all 256 probes at
            # the wrong port.
            res = await run_non_sym_side(
                bind_ip=bind_ip,
                known_port=self.our_known_port(),
                peer_ext_ip=peer_addr_ip,
                nonce=nonce,
                probe_count=probe_count,
                listen_timeout=PROBE_LISTEN_TIMEOUT,
                sock=getattr(self, "prebound_sock", None),
            )
        else:
            res = await run_symmetric_side(
                bind_ip=bind_ip,
                cone_ext_ip=peer_addr_ip,
                cone_ext_port=peer_known_port,
                nonce=nonce,
                probe_count=probe_count,
                listen_timeout=PROBE_LISTEN_TIMEOUT,
            )

        if res is None:
            log("RandomProbePlugin: round did not converge; aborting")
            if not self.result.done():
                self.result.set_result(None)
            return

        # Drain any probe datagrams still queued in the kernel
        # buffer for the winning socket before handing it up to
        # the user as a Pipe.  Without this, pipe.recv() returns
        # leftover probe bytes (sym's 256-pack, late cone probes,
        # the post-CONFIRM ROLE_SYM acknowledgement) instead of the
        # application's first real message.
        drained = drain_probe_residue(res["sock"], nonce)
        log("RandomProbePlugin: drained {0} residual probe(s) "
            "from winning sock".format(drained))

        # Wrap the winning UDP socket in a Pipe directly, *without*
        # calling sock.connect(peer) first.  Connecting a UDP socket
        # has two side-effects we don't want here:
        #   1. Inbound is filtered to the connected peer only.  If
        #      the peer's NAT remaps the source for any subsequent
        #      datagram (common on symmetric / port-restricted
        #      NATs), recvfrom returns nothing -- no echo reply.
        #   2. Outbound sendto(data, addr) fails when addr != the
        #      connected peer.  The echo handler (and any other
        #      msg_cb that replies with an explicit client_tup)
        #      breaks.
        # An unconnected socket wrapped in a Pipe accepts inbound
        # from any source and lets sendto target the actual reply
        # address pulled from datagram_received's addr arg.
        #
        # We don't go through sock_to_pipe because that helper
        # calls getpeername() on the sock to derive the dest tuple,
        # which only works on connected sockets.  We already have
        # res["peer"] from the convergence step, so build the Pipe
        # by hand.
        try:
            route = await self.nic.route(self.af).bind()
        except (OSError, ValueError):
            log("RandomProbePlugin: route bind failed for pipe wrap")
            if not self.result.done():
                self.result.set_result(None)
            return

        # Reuse the bind port the winning socket is on so the route
        # carries the right local port info downstream.
        try:
            local_port = res["sock"].getsockname()[1]
            await route.bind(port=local_port)
        except (OSError, AttributeError):
            pass

        try:
            from aionetiface import Pipe, UDP
            pipe = await Pipe(
                UDP,
                dest=res["peer"],
                route=route,
                sock=res["sock"],
            ).connect()
        except (OSError, ConnectionError, ValueError):
            log("RandomProbePlugin: Pipe wrap failed")
            if not self.result.done():
                self.result.set_result(None)
            return

        log("RandomProbePlugin: returning pipe role={0} sock={1!r} peer={2}".format(
            my_role, res["sock"], res["peer"]))
        if not self.result.done():
            self.result.set_result(pipe)

    # ── helpers ─────────────────────────────────────────────────

    def set_failed_result(self) -> None:
        """Resolve self.result with None so node.connect returns
        promptly instead of waiting out the plugin timeout."""
        if not self.result.done():
            self.result.set_result(None)

    def build_msg(self, role: str, punch_time: int, magic: str) -> RandomProbeMsg:
        """Build the RandomProbeMsg this side sends to its peer.

        ext_ip in the payload carries whichever address the algorithm
        will actually fire at:
          * STUN-discovered mapped IP (highest priority -- this is
            the real external address on a NAT'd host).
          * self.my_addr_ip (NIC if same_machine, ext otherwise) as
            the fallback when STUN didn't run (sym side) or didn't
            return a mapping.
        """
        ext_ip = (
            getattr(self, "mapped_ip", None)
            or getattr(self, "my_addr_ip", "")
            or ""
        )
        return RandomProbeMsg({
            "payload": {
                "role": role,
                "punch_time": int(punch_time),
                "magic": magic,
                "ext_ip": str(ext_ip),
                "known_port": self.our_known_port(),
                "probe_count": DEFAULT_PROBE_COUNT,
            },
        })

    async def prebind_non_sym_sock(self) -> None:
        """Bind the non-sym side's UDP socket *before* signaling +
        STUN-discover the (mapped_ip, mapped_port) it lands at.

        Stashed on self.prebound_sock and reused by run_non_sym_side
        at fire time.  The peer needs the *mapped* (external) IP and
        port to aim at, not the local bind port -- on a real NAT the
        external port is whatever the router assigned, not necessarily
        the local source port.  Without this STUN step the peer fires
        256 probes at a port the cone's NAT has no mapping for, every
        one gets dropped at the cone's NAT, and the round can never
        converge.

        Falls back to (local_ip, local_port) when no STUN servers are
        available or the queries time out -- in that case the
        algorithm only works on full-cone NATs that happen to do port
        preservation, which matches the pre-STUN behaviour and is
        still useful for same-machine / loopback testing.
        """
        try:
            route = await self.nic.route(self.af).bind()
        except (OSError, ValueError):
            log("RandomProbePlugin: pre-bind route bind failed")
            return
        try:
            self.prebound_sock = make_udp_socket(str(route.nic()), 0)
            self.prebound_port = self.prebound_sock.getsockname()[1]
        except OSError:
            log("RandomProbePlugin: pre-bind UDP socket failed")
            self.prebound_sock = None
            self.prebound_port = 0
            return

        # STUN-discover the external mapping.  We pull UDP STUN
        # servers via get_infra (the existing node.stun_clients are
        # TCP-only -- they're for the punch plugin) and try each in
        # turn; the first one that replies wins.  On total failure
        # we leave self.mapped_* unset and fall back to the local
        # port (cone-NAT-with-port-preservation case + same-machine
        # local tests where there's no NAT in the path).
        self.mapped_ip = None
        self.mapped_port = None
        stun_servers = self.udp_stun_servers()
        if not stun_servers:
            log("RandomProbePlugin: no UDP STUN servers available, "
                "advertising local port as known_port (works only "
                "for full-cone-with-port-preservation peers)")
            return

        loop = asyncio.get_event_loop()
        for stun_server in stun_servers:
            try:
                resolved = await self.resolve_stun_dest(stun_server)
            except (OSError, ConnectionError, asyncio.TimeoutError):
                continue
            mapping = await stun_discover_mapping(
                loop, self.prebound_sock, resolved, self.af,
                timeout=2.0, retries=2,
            )
            if mapping is not None:
                self.mapped_ip, self.mapped_port = mapping
                log("RandomProbePlugin: STUN discovered mapping "
                    "{0}:{1} for prebound local port {2}".format(
                        self.mapped_ip, self.mapped_port,
                        self.prebound_port,
                    ))
                return
        log("RandomProbePlugin: STUN discovery failed on all servers; "
            "falling back to local port {0}".format(self.prebound_port))

    def udp_stun_servers(self) -> List[Tuple[str, int]]:
        """Return up to 4 UDP STUN server (ip, port) tuples for our AF.

        Pulls from aionetiface's get_infra rather than node.stun_clients
        because the latter holds *TCP* STUN clients used by the punch
        plugin -- random_probe is UDP-only and needs UDP servers.
        """
        try:
            from aionetiface import get_infra, UDP
        except ImportError:
            return []
        try:
            entries = get_infra(self.af, UDP, "STUN(see_ip)", no=4)
        except (KeyError, ValueError):
            return []
        out = []
        for entry in entries:
            # get_infra returns lists of dicts; first dict has ip/port.
            try:
                rec = entry[0] if isinstance(entry, list) else entry
                out.append((rec["ip"], int(rec["port"])))
            except (KeyError, IndexError, TypeError, ValueError):
                continue
        return out

    async def resolve_stun_dest(self, dest: Tuple[str, int]) -> Tuple[str, int]:
        """DNS-resolve *dest* using the plugin's NIC + AF context."""
        from aionetiface import resolv_dest
        return await resolv_dest(self.af, dest, self.nic)

    def our_known_port(self) -> int:
        """Non-symmetric side's known external port; 0 if we're sym."""
        if is_symmetric_nat(self.src_info.get("nat") or {}):
            return 0
        # Prefer the STUN-discovered mapped port -- that's the port
        # the peer's probes actually need to target on a real NAT.
        mapped = getattr(self, "mapped_port", None)
        if mapped:
            return int(mapped)
        # Fall back to the local prebind port: only correct when the
        # NAT does port preservation (full cone, single ext = local)
        # or when there's no NAT at all (same-machine / loopback).
        prebound = getattr(self, "prebound_port", 0)
        if prebound:
            return int(prebound)
        bp = self.src_info.get("bind_port") or 0
        return int(bp)


def p_or_default(key: str) -> float:
    """Look up *key* in FAST_PUNCH_PARAMS with a sensible fallback."""
    return float(FAST_PUNCH_PARAMS.get(key, 8.0))


class RandomProbePluginFactory:
    """Builds RandomProbePlugin instances with a shared SysClock.

    UDP STUN servers are pulled on-demand via get_infra inside
    prebind_non_sym_sock (the node's own stun_clients dict is TCP,
    used by the punch plugin).
    """

    def __init__(self, sys_clock: Optional[Any] = None) -> None:
        self.sys_clock = sys_clock or SysClock(None, 0.1)

    def build_plugin(self) -> "RandomProbePlugin":
        """Create a new RandomProbePlugin wired to this factory's SysClock."""
        plugin = RandomProbePlugin()
        plugin.sys_clock = self.sys_clock
        return plugin

    async def close(self) -> None:
        """No-op: the factory holds no socket / process state."""
        return None


PLUGIN_CONF = {"timeout": 30}


async def setup_plugin(node: Any) -> RandomProbePluginFactory:
    """Discovered by plugin_loader; injects node.sys_clock into the factory."""
    return RandomProbePluginFactory(sys_clock=node.sys_clock)


# ─────────────────────────────────────────────────────────────────
# Design note: why UDP, not TCP
# ─────────────────────────────────────────────────────────────────
# The punch plugin uses TCP because port prediction (predictable
# symmetric or LAN) gives both sides a fixed target before they
# fire, so simultaneous-open is workable.  The random-probe path
# does NOT have a fixed target: the symmetric side burns a fresh
# external port per probe and the cone side has to land a SYN on
# one of those random ports while the symmetric NAT still treats
# it as "established" rather than dropping it as unsolicited.
# That's a much narrower race than UDP's "any datagram delivered
# wins", and many consumer NATs / Windows TCP stacks drop the
# inbound SYN-on-our-mapping case outright.  Tailscale's blog is
# explicit that their random-probe path is UDP-only; this plugin
# follows suit.
