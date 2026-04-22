"""Boundary-based port allocator for NAT prediction."""
import os
from ..utility.boundary_lib import *
from ..punch_defs import *


def boundary_port_alloc(timestamp, n=NUM_PORTS, params=None):
    # type: (int, int, Optional[Dict[str, Any]]) -> Tuple[List[Any], int]
    """
    Deterministic port allocation seeded by the NTP-aligned time bucket.

    params: optional punch parameter dict (see boundary_lib.DEFAULT_PUNCH_PARAMS /
            FAST_PUNCH_PARAMS).  When None the DEFAULT_PUNCH_PARAMS values are used
            so that existing callers that omit params keep the current behaviour.
    """
    p = params if params is not None else DEFAULT_PUNCH_PARAMS
    bucket, _ = compute_rendezvous(
        timestamp,
        window=p["window"],
        min_run_window=p["min_run_window"],
        max_error=p["max_clock_error"],
    )
    boundary = stable_boundary(bucket)
    if "P2PD_DEBUG" in os.environ:
        print("bucket = ", bucket)
        print("boundary = ", boundary)

    # Same src and dest port for this allocation type.
    ret = []
    ports = stable_ports(boundary, num_ports=n)
    for port in ports:
        ret.append(PortAlloc(port, port))

    return ret, 1
