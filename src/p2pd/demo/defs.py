"""Constants and shared state for the p2pd demo."""
from aionetiface import (
    dict_child, NET_CONF, get_aionetiface_install_root,
    OPEN_INTERNET, SYMMETRIC_UDP_FIREWALL, FULL_CONE, RESTRICT_NAT,
    RESTRICT_PORT_NAT, SYMMETRIC_NAT, BLOCKED_NAT,
    NA_DELTA, EQUAL_DELTA, PRESERV_DELTA, INDEPENDENT_DELTA,
    DEPENDENT_DELTA, RANDOM_DELTA,
)

IS_DEBUG = 2

demo_node_conf = dict_child(
    {
        "init_clock_skew": True,
        "reuse_addr": False,
        "enable_upnp": True,
        "sig_pipe_no": 1,
        "enable_punching": True,
        "enable_nickname": True,
        "enable_stun_clients": True,
        "install_path": get_aionetiface_install_root(),
    },
    NET_CONF,
)

nat_txt = {
    OPEN_INTERNET: "open internet",
    SYMMETRIC_UDP_FIREWALL: "udp firewall",
    FULL_CONE: "full cone",
    RESTRICT_NAT: "restrict",
    RESTRICT_PORT_NAT: "restrict port",
    SYMMETRIC_NAT: "symmetric",
    BLOCKED_NAT: "blocked",
}

delta_txt = {
    NA_DELTA: "not applicable",
    EQUAL_DELTA: "equal",
    PRESERV_DELTA: "preserving",
    INDEPENDENT_DELTA: "independent",
    DEPENDENT_DELTA: "dependent",
    RANDOM_DELTA: "random",
}

method_txt = {
    "d": "direct_connect",
    "r": "reverse_connect",
    "p": "punch",
    "t": "relay",
}

PROGRAM_BANNER = """Universal reachability demo
Coded by matthew@roberts.pm
-----------------------------
"""

MENU_BANNER = """(0) Connect to a node using its nickname or address.
(1) Start accepting connections (this stops the input loop)
(2) Register a unique nickname for your node.
(3) Exit program.
"""
