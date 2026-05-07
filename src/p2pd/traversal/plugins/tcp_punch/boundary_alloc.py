"""Boundary-based port allocator for NAT prediction."""
from typing import Any, Dict, List, Optional, Tuple
import os
from .boundary_lib import (
    compute_rendezvous, stable_boundary, stable_ports,
    NUM_PORTS, DEFAULT_PUNCH_PARAMS,
    port_pool_for_os, DEFAULT_PORT_POOL,
)
from .punch_defs import PortAlloc


def boundary_port_alloc(
    timestamp: int,
    n: int = NUM_PORTS,
    params: Optional[Dict[str, Any]] = None,
    our_os: Optional[str] = None,
    their_os: Optional[str] = None,
) -> Tuple[List[Any], int]:
    """
    Deterministic port allocation seeded by the NTP-aligned time bucket.

    params: optional punch parameter dict (see boundary_lib.DEFAULT_PUNCH_PARAMS /
            FAST_PUNCH_PARAMS). When None the DEFAULT_PUNCH_PARAMS values are
            used so existing callers that omit params keep the current behaviour.

    our_os, their_os: optional OS tokens for each peer (e.g. "winxp", "linux").
            Each returned PortAlloc contains (our_local_bind_port,
            peer_local_bind_port_we_connect_to). When both peers run identical
            OS pools the result matches the historical symmetric (port, port)
            shape; when one side is XP we pick its ports from the 1025-5000
            classifier-validated pool so the router NAT mapping matches the
            EQUAL_DELTA prediction. None defaults to the default pool.
    """
    p = params if params is not None else DEFAULT_PUNCH_PARAMS
    bucket, _ = compute_rendezvous(
        timestamp,
        window=p["window"],
        min_run_window=p["min_run_window"],
        max_error=p["max_clock_error"],
    )
    boundary = stable_boundary(bucket)

    our_base, our_range = port_pool_for_os(our_os)
    their_base, their_range = port_pool_for_os(their_os)

    # Always log -- single line per punch attempt, not hot.
    print(
        "boundary_port_alloc: timestamp={0} bucket={1} boundary={2} "
        "window={3} max_clock_error={4} num_ports={5} "
        "our_os={6} our_pool=[{7},{8}] their_os={9} their_pool=[{10},{11}]".format(
            timestamp, bucket, boundary,
            p["window"], p["max_clock_error"], n,
            our_os, our_base, our_base + our_range - 1,
            their_os, their_base, their_base + their_range - 1,
        ),
        flush=True,
    )

    our_ports = stable_ports(
        boundary, num_ports=n,
        base_port=our_base, port_range=our_range,
    )
    # When the pools match exactly (same OS on both sides, or both
    # default) the PRNG produces the same set so dest_port == src_port
    # and we keep the historical symmetric shape. Cross-OS pairs (e.g.
    # XP <-> Linux) get distinct port sets so each side connects to
    # the other's actual bind range.
    if (our_base, our_range) == (their_base, their_range):
        their_ports = our_ports
    else:
        their_ports = stable_ports(
            boundary, num_ports=n,
            base_port=their_base, port_range=their_range,
        )

    ret = []
    for i in range(min(len(our_ports), len(their_ports))):
        ret.append(PortAlloc(our_ports[i], their_ports[i]))

    return ret, 1
