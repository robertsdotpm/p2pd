"""
Shared helpers for the test_demo_smoke.* split test files.

The original test_demo_smoke.py grew several heavy two-node connectivity
classes that, when run in the same unittest subprocess, accumulated MQTT
client / dispatcher / socket state across tests. The runner runs each
test_*.py file in its own subprocess, so splitting the heavy classes into
separate files keeps each set of tests in a fresh process. These helpers
live here so each split file does not duplicate them.

Ports: each split file uses a disjoint sub-range under BASE_PORT to avoid
collisions when the runner schedules multiple test files in parallel.
"""

import asyncio
from aionetiface import (
    Interface,
    dict_child, list_interfaces, load_interfaces,
)
from warpgate.node.node_defs import NODE_TEST_CONF, NODE_PORT


BASE_PORT = NODE_PORT + 4000


# Demo uses full conf but tests stay fast by disabling the slow bits.
# sig_pipe_no=1 lets two nodes on the same machine reach each other via MQTT;
# set to 0 for pure same-machine tests that rely only on direct TCP.
DEMO_SMOKE_CONF = dict_child(
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


async def load_demo_ifs():
    """Load interfaces the same way the demo does: real NIC discovery, no NAT detection."""
    if_names = await list_interfaces()
    return await load_interfaces(if_names, Interface, skip_nat=True)


async def start_demo_node(port, ifs=None):
    """Start a node using demo-style interface loading.

    Imported lazily so split test files that don't need a Node don't pay
    the import cost (and don't tangle helper-loading errors with their
    own setup failures).
    """
    from warpgate import Node
    if ifs is None:
        ifs = await load_demo_ifs()
    node = Node(ifs=ifs, port=port, conf=DEMO_SMOKE_CONF)
    await asyncio.wait_for(node.start(), timeout=40)
    return node


async def close_nodes(*nodes):
    for node in nodes:
        if node is not None:
            try:
                await asyncio.wait_for(node.close(), timeout=10)
            except Exception:
                pass
