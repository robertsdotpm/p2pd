"""
Using offsets for servers is a bad idea as server
lists need to be updated. Use short, unique IDs or
index by host name even if its longer.
"""

from typing import Any, Tuple
import asyncio
import time
from aionetiface import fstr, log, to_s
from .node_defs import CON_ID_MSG
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
    """Dispatch each newline-delimited message from the pipe to handle_msg and all registered callbacks."""
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
        coros.append(handle_msg(node, m, client_tup, pipe))
        for cb in node.msg_cbs:
            coros.append(cb(m, client_tup, pipe))

    results = await asyncio.gather(*coros, return_exceptions=True)
    for r in results:
        if isinstance(r, KeyboardInterrupt):
            log("reraising key interrupt")
            raise r
        if isinstance(r, Exception):
            log("msg_cb coro raised: " + repr(r))


async def handle_msg(node: Any, msg: bytes, client_tup: Tuple[str, int], pipe: Any) -> None:
    """Parse a single node protocol message and act on recognised commands such as CON_ID_MSG."""
    log(
        fstr(
            "> node proto = {0}, {1}",
            (
                msg,
                client_tup,
            ),
        )
    )

    if msg == b"long_p2pd_test_string_abcd123":
        await pipe.send(b"p2pd test string\r\n\r\n", client_tup)
        return

    parts = msg.split(b" ")
    cmd = parts[0]

    if cmd == CON_ID_MSG:
        if len(parts) != 2:
            log("ID: Invalid parts len.")
            return
        node.pipe_ready(to_s(parts[1]), pipe)
