import time
from ..lib.boundary_lib import *
from ..punch_defs import *

def boundary_port_alloc(timestamp, n=NUM_PORTS):
    bucket, punch_time = compute_rendezvous(timestamp)
    boundary = stable_boundary(bucket)
    print("bucket = ", bucket)
    print("future punch time = ", punch_time)
    print("boundary = ", boundary)


    # Same src and dest port for this allocation type.
    ret = []
    ports = stable_ports(boundary, num_ports=n)
    for port in ports:
        ret.append(PortAlloc(port, port))

    return (ret, punch_time,)
