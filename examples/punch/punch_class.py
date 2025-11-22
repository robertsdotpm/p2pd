"""
Design:

    - timing strategies:
        - ntp reference + future time
        - could also be based on receive time + future offset
            - requires communication between hosts

    - existing code:
        - partial success:
            - use initial predicted mappings

        - response:
            - use their predicted mappings

    - full graceful degrade:
        - timing: ntp assumed in same window
        - deterministic mappings -> same port
            - no predictions for mappings
        - connect + listen select engine
        - works well to test algorithm behind LAN and simple NATs
        - no communication between hosts

    - future work 

        - "hard side" + "easy side" UDP algorithm:
            - hard side:
                - 256 sockets and outbound cons to same easy ip:port
            - easy side:
                - 1 socket and 256 multiplexed sends to random hard ip:ports
                - src NAT preserves same ip:port alloc for send
                - collision ends up with 66% success for hard side
            - requirements:
                - NAT-specific tuple allocation iter for: src bind, src ip, dest ip dest port
                    - socket set(src ip, src port) reuse based on proto (only for UDP)
            - reference:
                - "https://tailscale.com/blog/how-nat-traversal-works" (NAT notes for nerds)
        - 

    - limitations:
        - FD limit on windows is 64
"""
import argparse
import socket
from .punch_defs import *
from .port_allocators.boundary_alloc import *

parser = argparse.ArgumentParser(description="Test main punching algorithm")
parser.add_argument("--dest_ip", type=str, required=True, help="Dest IP to punch to")

# TODO: Could even use ARP to find the other node in a LAN
# running the same tool so the dest IP doesn't have to be specified.
class Punch():
    def __init__(self, dest_ip):
        # Fallback to IP4
        self.af = socket.AF_INET
        if ":" in dest_ip:
            self.af = socket.AF_INET6

        # Fallback to default interface.
        self.src_ip = "0.0.0.0" 
        self.dest_ip = dest_ip

        # Listen bind / dest connect matrixes.
        self.port_allocs = [] # [ src bind, dest port ]

        # Start punching in 10 seconds by defaul.
        self.punch_time = 10

    def set_src_ip(self, src_ip):
        self.src_ip = src_ip

    def set_af(self, af):
        self.af = af

    def add_port_allocator(self, f_port_alloc):
        port_allocs, punch_time = f_port_alloc()
        for port_alloc in port_allocs:
            is_unique = True
            for stored_port_alloc in self.port_alloc:
                if tuple(port_alloc) == tuple(stored_port_alloc):
                    is_unique = False

                    break

            if is_unique:
                self.port_allocs.append(port_alloc)

        self.punch_time = min(self.punch_time, punch_time)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test main punching algorithm")
    parser.add_argument(
        "--dest_ip",
        type=str,
        required=True,
        help="Dest IP to punch to"
    )
    args = parser.parse_args()
    punch = Punch(args.dest_ip)

