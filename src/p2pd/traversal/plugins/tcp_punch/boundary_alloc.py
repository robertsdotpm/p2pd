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
    Two-bucket overlapping port pool seeded by the NTP-aligned time bucket.

    Returns ports drawn from BOTH bucket B and bucket B+1, where B is
    the primary bucket compute_rendezvous picks for `timestamp`.  Two
    peers whose `compute_rendezvous` calls land on opposite sides of a
    boundary -- one picks B, the other picks B+1 -- still share a common
    bucket in their port-allocation sets:

        peer in bucket B   -> ports drawn from {B,   B+1}
        peer in bucket B+1 -> ports drawn from {B+1, B+2}
        intersection        =  ports of bucket B+1

    The fundamental fork rate of any deterministic single-bucket
    quantization is delta/window where delta is the call-time gap
    between peers (clock skew + signal-channel latency).  With MQTT
    signaling latency of 1-3s typical and window=42s, that's ~5%
    fork per attempt -- empirically observable in the matrix as 42s
    punch_time misalignment between connector and listener even when
    NTP residuals are sub-second.  Drawing ports from two buckets
    converts the fork from a binary "miss / hit" into a guaranteed
    overlap regardless of which side of the boundary each peer lands.

    n is the TOTAL port count returned (split as n//2 from each
    bucket).  Default NUM_PORTS=16 yields 8 from B + 8 from B+1, which
    keeps the per-fire half-open SYN count at 16 (same as before this
    change) and leaves headroom under XP's 10-concurrent-half-open
    cap (Tcpip Event 4226).  Bumping n to 32 to keep 16 per bucket
    would double per-fire load and risk tripping XP -- if a future
    sweep shows convergence loss from halving per-bucket count, raise
    n to 32 only after confirming XP isn't queuing excess SYNs.

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
    primary_bucket, _ = compute_rendezvous(
        timestamp,
        window=p["window"],
        min_run_window=p["min_run_window"],
        max_error=p["max_clock_error"],
    )

    # Split n across the two buckets so the per-fire SYN count stays
    # at the historical NUM_PORTS=16 value (8 + 8) -- staying under XP's
    # 10-concurrent-half-open cap with the existing 5ms spray cadence.
    n_per_bucket = max(1, n // 2)

    our_base, our_range = port_pool_for_os(our_os)
    their_base, their_range = port_pool_for_os(their_os)
    pools_match = (our_base, our_range) == (their_base, their_range)

    print(
        "boundary_port_alloc: timestamp={0} primary_bucket={1} "
        "buckets=[{1},{2}] n_total={3} n_per_bucket={4} "
        "window={5} max_clock_error={6} "
        "our_os={7} our_pool=[{8},{9}] their_os={10} their_pool=[{11},{12}]".format(
            timestamp, primary_bucket, primary_bucket + 1,
            n, n_per_bucket,
            p["window"], p["max_clock_error"],
            our_os, our_base, our_base + our_range - 1,
            their_os, their_base, their_base + their_range - 1,
        ),
        flush=True,
    )

    ret = []
    for bucket in (primary_bucket, primary_bucket + 1):
        boundary = stable_boundary(bucket)
        our_ports = stable_ports(
            boundary, num_ports=n_per_bucket,
            base_port=our_base, port_range=our_range,
        )
        # When the pools match exactly (same OS on both sides, or both
        # default) the PRNG produces the same set so dest_port == src_port
        # and we keep the historical symmetric shape. Cross-OS pairs (e.g.
        # XP <-> Linux) get distinct port sets so each side connects to
        # the other's actual bind range.
        if pools_match:
            their_ports = our_ports
        else:
            their_ports = stable_ports(
                boundary, num_ports=n_per_bucket,
                base_port=their_base, port_range=their_range,
            )
        for i in range(min(len(our_ports), len(their_ports))):
            ret.append(PortAlloc(our_ports[i], their_ports[i]))

    return ret, 1
