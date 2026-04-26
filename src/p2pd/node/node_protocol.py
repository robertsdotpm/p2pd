"""
node_protocol is a dumb proxy.

The historical CON_ID_MSG in-band handshake (the responder's "this TCP
pipe belongs to plugin X" announcement) has moved to a SIG_CON_ID
signal over the MQTT router. With that out of the way, node_protocol
no longer needs to peek at the first datagram on every inbound pipe;
it just splits TCP frames on newline and fans out to whichever msg_cbs
the application has registered.
"""

from typing import Any, Tuple
import asyncio
import time
from aionetiface import log
from ..traversal.plugins.random_probe.random_probe_defs import (
    PROBE_LEN,
    PROBE_MAGIC,
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


async def node_protocol(node: Any, msg: bytes, client_tup: Tuple[str, int], pipe: Any) -> None:
    """Dispatch each newline-delimited message from the pipe to all registered msg_cbs."""
    print("Node proto: ", msg)

    # Drop residual random_probe probe datagrams: they're algorithm
    # artefacts, not application data, and dispatching them through
    # node_protocol just hands probe bytes up to the user's
    # msg_cbs.  Cheap predicate (length + 4-byte magic) so this is
    # safe to run unconditionally on every inbound.
    if is_random_probe_datagram(msg):
        return

    # Track idle pipe recv time.
    if pipe in node.resources.last_recv_queue:
        node.resources.last_recv_table[pipe.sock] = time.time()

    # TCP may buffer multiple messages — split and dispatch each.
    coros = []
    for m in msg.split(b"\n"):
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
