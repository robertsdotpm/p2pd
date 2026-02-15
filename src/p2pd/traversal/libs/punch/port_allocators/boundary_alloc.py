import time
import os
from ..utility.boundary_lib import *
from ..punch_defs import *

def boundary_port_alloc(timestamp, n=NUM_PORTS):
    bucket, _ = compute_rendezvous(timestamp)
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
