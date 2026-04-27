"""
node_protocol is a dumb proxy + a one-shot ConId rendezvous peeler.

Each inbound TCP pipe's first message is expected to be a
b"P2P-CID:<plugin_id>\\n" frame written by the initiator's
direct_connect right after the TCP connect succeeds. We peel it off
here, resolve the reverse_connect inbound future for plugin_id, and
let everything after that flow through the registered msg_cbs as
normal data. One channel for connect + rendezvous, no cross-channel
race.
"""

from typing import Any, Tuple
import asyncio
import time
from aionetiface import log, to_s
from ..traversal.plugins.direct_connect.con_id_frame import CON_ID_PREFIX
from ..traversal.plugins.random_probe.random_probe_defs import (
    PROBE_LEN,
    PROBE_MAGIC,
)
from ..traversal.plugins.udp_punch.udp_punch_defs import (
    UDP_PUNCH_FRAME_LEN,
    UDP_PUNCH_MAGIC,
)


def is_random_probe_datagram(msg: bytes) -> bool:
    """True iff *msg* looks like a stray random_probe probe.

    Probe datagrams have a fixed length and a fixed 4-byte magic
    prefix.  After convergence the symmetric side's 256-pack can
    keep arriving for hundreds of ms (CGNAT / mobile-carrier
    paths) and the cone's NIC keeps queueing them on the live
    Pipe; without this filter pipe.recv() returns those raw
    bytes to the application instead of the first real payload.
    """
    return len(msg) == PROBE_LEN and msg[:4] == PROBE_MAGIC


def is_udp_punch_datagram(msg: bytes) -> bool:
    """True iff *msg* looks like a stray udp_punch PROBE / CONFIRM frame.

    Same shape problem as random_probe: after convergence the engine's
    spray keeps arriving on the winning socket for hundreds of ms;
    those frames get queued on the wrapped Pipe and dispatched to
    application msg_cbs unless we filter them out here. Cheap predicate
    (fixed length + 4-byte magic) so it's safe to run on every inbound.
    """
    return len(msg) == UDP_PUNCH_FRAME_LEN and msg[:4] == UDP_PUNCH_MAGIC


async def node_protocol(node: Any, msg: bytes, client_tup: Tuple[str, int], pipe: Any) -> None:
    """Dispatch each newline-delimited message from the pipe to all registered msg_cbs."""
    print("Node proto: ", msg)

    # Drop residual algorithm frames (random_probe probes, udp_punch
    # PROBE/CONFIRM): both protocols keep spraying for hundreds of ms
    # past convergence; without these filters the post-wrap Pipe
    # delivers raw frame bytes to the user's msg_cbs.
    if is_random_probe_datagram(msg):
        return
    if is_udp_punch_datagram(msg):
        return

    # Track idle pipe recv time.
    if pipe in node.resources.last_recv_queue:
        node.resources.last_recv_table[pipe.sock] = time.time()

    # TCP may buffer multiple messages — split and dispatch each.
    coros = []
    for m in msg.split(b"\n"):
        # In-band ConId rendezvous: the very first frame on every
        # direct_connect inbound pipe is b"P2P-CID:<plugin_id>".
        # Peel it off, resolve the reverse_connect future, and keep
        # walking the remaining frames in this batch. One-shot per
        # pipe (con_id_seen guards against repeat rendezvous on the
        # rare chance a payload happens to start with the prefix).
        if not getattr(pipe, "con_id_seen", False) and m.startswith(CON_ID_PREFIX):
            plugin_id = to_s(m[len(CON_ID_PREFIX):])
            pipe.con_id_seen = True
            print("[CON-ID-RX] in-band ConId pipe={0!r} plugin_id={1!r}".format(
                pipe, plugin_id,
            ))
            if node.traversal is not None:
                node.traversal.resolve_inbound_by_plugin_id(plugin_id, pipe)
            continue
        if m == b"long_p2pd_test_string_abcd123":
            # Reachability probe used by remote_reachability_cb / matrix
            # smoke checks. Echo back and skip msg_cbs -- it isn't
            # application traffic.
            await pipe.send(b"p2pd test string\r\n\r\n", client_tup)
            continue
        for cb in node.msg_cbs:
            coros.append(cb(m, client_tup, pipe))

    if not coros:
        return

    results = await asyncio.gather(*coros, return_exceptions=True)
    for r in results:
        if isinstance(r, KeyboardInterrupt):
            log("reraising key interrupt")
            raise r
        if isinstance(r, Exception):
            log("msg_cb coro raised: " + repr(r))
