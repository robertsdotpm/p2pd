import time
from ..lib.boundary_lib import *
from ..punch_defs import *

def alloc_ports(n=NUM_PORTS, ntp=None):
    now = ntp or int(time.time())
    bucket, punch_time = compute_rendezvous(now)
    boundary = stable_boundary(bucket)

    # Same src and dest port for this allocation type.
    ret = []
    ports = stable_ports(boundary, num_ports=n)
    for port in ports:
        ret.append(PortAlloc(port, port))

    return (ret, punch_time,)
