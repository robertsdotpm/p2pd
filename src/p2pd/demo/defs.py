from ..do_imports import *

IS_DEBUG = 2

node_conf = dict_child({
    "init_clock_skew": True,
    "reuse_addr": False,
    "enable_upnp": True,
    "sig_pipe_no": SIGNAL_PIPE_NO,
    "enable_punching": True,
    "enable_nickname": True,
    "enable_stun_clients": True,
    "install_path": get_p2pd_install_root()
}, NET_CONF)

nat_txt = {
    OPEN_INTERNET: "open internet",
    SYMMETRIC_UDP_FIREWALL: "udp firewall",
    FULL_CONE: "full cone",
    RESTRICT_NAT: "restrict",
    RESTRICT_PORT_NAT: "restrict port",
    SYMMETRIC_NAT: "symmetric",
    BLOCKED_NAT: "blocked"
}

delta_txt = {
    NA_DELTA: "not applicable",
    EQUAL_DELTA: "equal",
    PRESERV_DELTA: "preserving",
    INDEPENDENT_DELTA: "independent",
    DEPENDENT_DELTA: "dependent",
    RANDOM_DELTA: "random"
}

method_txt = {
    "d": P2P_DIRECT,
    "r": P2P_REVERSE,
    "p": P2P_PUNCH,
    "t": P2P_RELAY,
}