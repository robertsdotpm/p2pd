"""Boundary-based port allocator for NAT prediction."""
from typing import Any, Dict, List, Optional, Tuple
import os
from .boundary_lib import compute_rendezvous, stable_boundary, stable_ports, NUM_PORTS, DEFAULT_PUNCH_PARAMS
from .punch_defs import PortAlloc


def boundary_port_alloc(timestamp: int, n: int = NUM_PORTS, params: Optional[Dict[str, Any]] = None) -> Tuple[List[Any], int]:
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
    # Always log -- single line per punch attempt, not hot. The
    # timestamp is the SysClock-resolved Unix time the puncher saw
    # at compute time, which lets cross-host log diffs catch
    # bucket-boundary failures (peers in adjacent buckets) without
    # having to back-derive `now` from the bucket.
    print(
        "boundary_port_alloc: timestamp={0} bucket={1} boundary={2} "
        "window={3} max_clock_error={4} num_ports={5}".format(
            timestamp, bucket, boundary,
            p["window"], p["max_clock_error"], n,
        ),
        flush=True,
    )

    # Same src and dest port for this allocation type.
    ret = []
    ports = stable_ports(boundary, num_ports=n)
    for port in ports:
        ret.append(PortAlloc(port, port))

    return ret, 1
