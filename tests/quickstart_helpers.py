"""
Shared helpers for the test_docs_quickstart.* split test files.

The original test_docs_quickstart.py grew several heavy auto_connect /
msg_cb classes that, when run in the same unittest subprocess,
accumulated MQTT client / dispatcher / socket state across tests. The
runner runs each test_*.py file in its own subprocess, so splitting the
heavy classes into separate files keeps each set of tests in a fresh
process.

Ports: each split file uses a disjoint sub-range under BASE_PORT to avoid
collisions when the runner schedules multiple test files in parallel.
"""

import asyncio
from aionetiface import dict_child
from p2pd.node.node_defs import NODE_TEST_CONF, NODE_PORT


BASE_PORT = NODE_PORT + 3000


# Give signal-capable tests a sig_pipe so the MQTT router can relay signals.
# For pure same-machine direct tests, sig_pipe_no=0 is fine.
QUICKSTART_CONF = dict_child(
    {
        "sig_pipe_no": 1,
        "enable_upnp": False,
        "init_clock_skew": False,
        "enable_punching": False,
        "enable_nickname": False,
        "enable_stun_clients": False,
    },
    NODE_TEST_CONF,
)


async def close_nodes(*nodes):
    """Close all nodes, ignoring errors."""
    for node in nodes:
        if node is not None:
            try:
                await asyncio.wait_for(node.close(), timeout=10)
            except Exception:
                pass
