from .p2p_pipe import *
from .nat import *

TXT = {
    "p2p_strat": {
        P2P_DIRECT: "direct connect",
        P2P_REVERSE: "reverse connect",
        P2P_PUNCH: "tcp punch",
        P2P_RELAY: "turn relay"
    },
    "nat": {
        OPEN_INTERNET: "open internet (no NAT)",
        SYMMETRIC_UDP_FIREWALL: "possible firewall (no NAT)",
        FULL_CONE: "full cone",
        RESTRICT_NAT: "restrict reuse",
        RESTRICT_PORT_NAT: "restrict port",
        SYMMETRIC_NAT: "symetric",
        BLOCKED_NAT: "unknown (all responses blocked)"
    },
    "delta": {
        NA_DELTA: "not applicable",
        EQUAL_DELTA: "equal delta (local port == mapped port)",
        PRESERV_DELTA: "preserving delta ((local port + dist) == (mapped_start + dist))",
        INDEPENDENT_DELTA: "independent delta (rand port == (last_mapped += delta))",
        DEPENDENT_DELTA: "dependent delta ((local port += [1 to delta]) == (last_mapped += [1 to delta]))",
        RANDOM_DELTA: "random delta (local port == rand port)"
    }
}
