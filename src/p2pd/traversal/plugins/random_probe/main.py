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
from typing import Any, Dict, Optional, Tuple

from aionetiface import (
    EXT_BIND,
    SysClock,
    log,
    rand_b,
    to_b,
    to_s,
)
from aionetiface.nic.nat.nat_defs import FULL_CONE, OPEN_INTERNET, SYMMETRIC_NAT

from ....protocol.proto_msg import RandomProbeMsg
from ...traversal_plugin import TraversalPlugin
from ..punch.boundary_lib import FAST_PUNCH_PARAMS, compute_rendezvous

from .random_probe_defs import DEFAULT_PROBE_COUNT, PROBE_LISTEN_TIMEOUT
from .random_probe_lib import (
    run_cone_side,
    run_symmetric_side,
    wait_until,
)


# Cone-side NAT types: endpoint-independent mapping.  The peer can
# guess the external (ip, port) without help.
CONE_NATS = (OPEN_INTERNET, FULL_CONE)


def is_cone_nat(nat_info: Dict[str, Any]) -> bool:
    """True when *nat_info* describes an endpoint-independent NAT."""
    if not nat_info:
        return False
    return nat_info.get("type") in CONE_NATS


def is_symmetric_nat(nat_info: Dict[str, Any]) -> bool:
    """True when *nat_info* describes a symmetric NAT."""
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
        # Decide which side we are based on our own NAT type.
        # nat_info defaults to {} for clean attribute access.
        my_nat = self.src_info.get("nat") or {}
        peer_nat = self.dest_info.get("nat") or {}

        if is_cone_nat(my_nat) and is_symmetric_nat(peer_nat):
            my_role = "cone"
        elif is_symmetric_nat(my_nat) and is_cone_nat(peer_nat):
            my_role = "sym"
        else:
            log(
                "RandomProbePlugin: pair is not (cone, sym) "
                "(my={0}, peer={1}); aborting".format(
                    my_nat.get("type"), peer_nat.get("type"),
                )
            )
            return

        if reply is None:
            # Initiator: pick a session nonce + rendezvous time and
            # send a RandomProbeMsg out.  Stash both on self so we
            # can match them when the peer's reply arrives.
            self.session_nonce = rand_b(16)
            self.session_role = my_role
            timestamp = self.sys_clock.time()
            p = FAST_PUNCH_PARAMS
            _, punch_time = compute_rendezvous(
                timestamp,
                window=p["window"],
                min_run_window=p["min_run_window"],
                max_error=p["max_clock_error"],
            )
            self.punch_time = punch_time

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

        peer_ext_ip = reply.payload.ext_ip
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

        if my_role == "cone":
            our_known_port = self.our_known_port()
            res = await run_cone_side(
                bind_ip=bind_ip,
                known_port=our_known_port,
                peer_ext_ip=peer_ext_ip,
                nonce=nonce,
                probe_count=probe_count,
                listen_timeout=PROBE_LISTEN_TIMEOUT,
            )
        else:
            res = await run_symmetric_side(
                bind_ip=bind_ip,
                cone_ext_ip=peer_ext_ip,
                cone_ext_port=peer_known_port,
                nonce=nonce,
                probe_count=probe_count,
                listen_timeout=PROBE_LISTEN_TIMEOUT,
            )

        if not self.result.done():
            self.result.set_result(res)

    # ── helpers ─────────────────────────────────────────────────

    def build_msg(self, role: str, punch_time: int, magic: str) -> RandomProbeMsg:
        """Build the RandomProbeMsg this side sends to its peer."""
        ext_ip = str(self.src_info.get("ext") or "")
        return RandomProbeMsg({
            "payload": {
                "role": role,
                "punch_time": int(punch_time),
                "magic": magic,
                "ext_ip": ext_ip,
                "known_port": self.our_known_port(),
                "probe_count": DEFAULT_PROBE_COUNT,
            },
        })

    def our_known_port(self) -> int:
        """Cone side's known external port; 0 for the symmetric side."""
        if not is_cone_nat(self.src_info.get("nat") or {}):
            return 0
        # On a cone NAT the external port equals the local source port
        # we bind, so we just publish whatever bind_port the route
        # ended up with.  Fall back to 0 if the route hasn't bound yet
        # (in which case the cone side will bind on a random ephemeral
        # port at fire time and the symmetric side has nothing to aim
        # at -- the round simply fails).
        bp = self.src_info.get("bind_port") or 0
        return int(bp)


def p_or_default(key: str) -> float:
    """Look up *key* in FAST_PUNCH_PARAMS with a sensible fallback."""
    return float(FAST_PUNCH_PARAMS.get(key, 8.0))


PLUGIN_CLASS = RandomProbePlugin
PLUGIN_CONF = {"timeout": 30}


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
