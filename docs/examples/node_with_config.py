from p2pd import *

node_conf = dict_child({
    # Port forwarding (IPv4) and pin holes (IPv6)
    "enable_upnp": True,

    # MQTT server no -- need at least 1 for P2P connections.
    "sig_pipe_no": SIGNAL_PIPE_NO,
}, NET_CONF)

async def example():
    if_names = await list_interfaces()
    ifs = await load_interfaces(if_names)
    node = await P2PNode(ifs=ifs, port=1337, conf=node_conf)
    await node.close()