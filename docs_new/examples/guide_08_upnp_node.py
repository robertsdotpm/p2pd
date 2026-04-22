"""
Start a P2P node with UPnP port forwarding enabled.

UPnP lets the node ask your home router to open an external port so
that peers can reach it with a direct connection.  This reduces
reliance on hole punching or TURN relays.

Run:
    python3 docs/examples/guide_08_upnp_node.py

Note: UPnP must be enabled on your router.  The node will still work
if UPnP is unavailable -- it falls back to other traversal strategies.

Tests equivalent: tests/test_network.py
"""

from p2pd import *

node_conf = dict_child(
    {
        # Ask the router to open an external port via UPnP/IGD.
        "enable_upnp": True,
        # Number of MQTT signaling connections to maintain.
        "sig_pipe_no": SIGNAL_PIPE_NO,
    },
    NET_CONF,
)


async def msg_cb(msg, client_tup, pipe):
    if b"PING" in msg:
        await pipe.send(b"PONG", client_tup)


async def example():
    if_names = await list_interfaces()
    ifs = await load_interfaces(if_names)

    async with P2PNode(ifs=ifs, port=7890, conf=node_conf) as node:
        node.add_msg_cb(msg_cb)
        full_name = await node.nickname("upnpnode")
        print("UPnP node listening on port 7890")
        print("Nickname:", full_name)
        print("Address:", node.addr_bytes.decode())


if __name__ == "__main__":
    async_test(example)
