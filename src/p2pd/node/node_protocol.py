"""
Using offsets for servers is a bad idea as server
lists need to be updated. Use short, unique IDs or
index by host name even if its longer.
"""

import asyncio
import time
from aionetiface import *
from .node_defs import CON_ID_MSG


async def node_protocol(node, msg, client_tup, pipe):
    # type: (Any, bytes, Tuple[str, int], Any) -> None
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
        elif isinstance(r, Exception):
            log("msg_cb coro raised: " + repr(r))


async def handle_msg(node, msg, client_tup, pipe):
    # type: (Any, bytes, Tuple[str, int], Any) -> None
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
