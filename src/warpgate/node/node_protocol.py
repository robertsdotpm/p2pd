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


def is_random_probe_datagram(msg):
    """True iff *msg* looks like a stray random_probe probe.

    Probe datagrams have a fixed length and a fixed 4-byte magic
    prefix.  After convergence the symmetric side's 256-pack can
    keep arriving for hundreds of ms (CGNAT / mobile-carrier
    paths) and the cone's NIC keeps queueing them on the live
    Pipe; without this filter pipe.recv() returns those raw
    bytes to the application instead of the first real payload.
    """
    return len(msg) == PROBE_LEN and msg[:4] == PROBE_MAGIC


def is_udp_punch_datagram(msg):
    """True iff *msg* looks like a stray udp_punch PROBE / CONFIRM frame.

    Same shape problem as random_probe: after convergence the engine's
    spray keeps arriving on the winning socket for hundreds of ms;
    those frames get queued on the wrapped Pipe and dispatched to
    application msg_cbs unless we filter them out here. Cheap predicate
    (fixed length + 4-byte magic) so it's safe to run on every inbound.
    """
    return len(msg) == UDP_PUNCH_FRAME_LEN and msg[:4] == UDP_PUNCH_MAGIC


async def node_protocol(node, msg, client_tup, pipe):
    """Peel control frames at the start of the buffer, then dispatch the
    remaining bytes as a single opaque payload to every registered msg_cb.

    The earlier implementation split the whole inbound buffer on b"\\n",
    which silently dropped every b"\\n" byte in user payloads. Any binary
    stream that happened to contain newlines lost those bytes. Now we
    only peel control-plane frames -- the one-shot CON_ID rendezvous and
    the matrix reachability probe -- both of which are themselves newline-
    terminated. Everything after that flows through unchanged.
    """
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

    # In-band ConId rendezvous: the very first frame on every
    # direct_connect inbound pipe is b"P2P-CID:<plugin_id>\n".
    # Peel exactly that frame off (locating its terminating \n) so the
    # rest of the buffer -- which may be application bytes that the
    # peer already trailed onto the same TCP write -- flows through
    # untouched. One-shot per pipe (con_id_seen guards against repeat
    # rendezvous on the rare chance a payload happens to start with
    # the prefix).
    if not getattr(pipe, "con_id_seen", False) and msg.startswith(CON_ID_PREFIX):
        nl = msg.find(b"\n")
        if nl == -1:
            # Partial frame -- treat the whole buffer as the plugin_id,
            # nothing after.  Rare; direct_connect always appends \n.
            plugin_id = to_s(msg[len(CON_ID_PREFIX):])
            msg = b""
        else:
            plugin_id = to_s(msg[len(CON_ID_PREFIX):nl])
            msg = msg[nl + 1:]
        pipe.con_id_seen = True
        if node.traversal is not None:
            node.traversal.resolve_inbound_by_plugin_id(plugin_id, pipe)
        if not msg:
            return

    # Reachability probe used by remote_reachability_cb / matrix smoke
    # checks. Echo back and skip msg_cbs -- it isn't application traffic.
    # Tolerate trailing \n (the sender appends one) and peel off if more
    # data follows in the same TCP buffer.
    probe = b"long_warpgate_test_string_abcd123"
    if msg == probe or msg == probe + b"\n":
        await pipe.send(b"warpgate test string\r\n\r\n", client_tup)
        return
    if msg.startswith(probe + b"\n"):
        await pipe.send(b"warpgate test string\r\n\r\n", client_tup)
        msg = msg[len(probe) + 1:]
        if not msg:
            return

    # Deliver the remaining bytes as one opaque payload. Callers that
    # need framed messages must do their own length-prefix or escape
    # work -- a TCP stream doesn't preserve message boundaries.
    coros = []
    for cb in node.msg_cbs:
        coros.append(cb(msg, client_tup, pipe))

    if not coros:
        return

    results = await asyncio.gather(*coros, return_exceptions=True)
    for r in results:
        if isinstance(r, KeyboardInterrupt):
            log("reraising key interrupt")
            raise r
        if isinstance(r, Exception):
            log("msg_cb coro raised: " + repr(r))
