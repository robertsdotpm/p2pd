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

import sys
import argparse
import socket
import pickle
from aionetiface import *
from .punch_defs import *
from .port_allocators.boundary_alloc import *
from .engines.tcp_selector_simple.engine import *
from .utility.punch_utils import *


# TODO: Could even use ARP to find the other node in a LAN
# running the same tool so the dest IP doesn't have to be specified.
class PunchClient:
    def __init__(self, dest_ip, src_ip=None, our_ip=None, nic_id=None, max_sleep=10):
        # Fallback to IP4
        self.af = socket.AF_INET
        if ":" in dest_ip:
            self.af = socket.AF_INET6

        # Fallback to default interface.
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.our_ip = our_ip

        # NIC ID = name of a NIC or its number.
        # The value is needed mostly for IPv6.
        self.nic_id = nic_id
        if not nic_id and src_ip:
            # Try to extract the idea from % part of src_ip
            # if its found of course.
            if self.af == IP6 and "%" in src_ip:
                self.nic_id = src_ip.split("%")[1]
        
        # Listen bind / dest connect matrixes.
        self.port_allocs = [] # [ src bind, dest port ]

        # The allocator has to decide on this.
        # Relative time from start_time bellow.
        self.punch_time = 0

        # Default to inaccurate system clock.
        self.timestamp = int(time.time())
        self.start_time = time.monotonic()
        self.max_sleep = max_sleep

        # Sanity check -- don't punch to self.
        if our_ip and 0: # TODO: disabled
            if IPR(dest_ip, af=self.af) == IPR(our_ip, af=self.af):
                """
                No longer want to maintain bizzare and useless features.
                There's no reason to do this, not even for testing.
                Testing can be done from VMs or virtual interfaces.
                """
                raise Exception("Punching to self is not supported.")
            
        # Normalise all ips.
        # This strips all cidrs, $ stuff etc.
        self.dest_ip = ip_norm(self.dest_ip)
        if self.src_ip: 
            self.src_ip = ip_norm(self.src_ip)
        if self.our_ip:
            self.our_ip = ip_norm(self.our_ip)
            
        # Patch dest IP based on special bind rules.
        self.dest_ip = patch_connect_ip(
            self.af, 
            self.dest_ip,
            self.nic_id
        )

        print(self.dest_ip)

    def set_src_ip(self, src_ip):
        self.src_ip = src_ip

    # Timestamp is a unix timestamp.
    def set_timestamp(self, timestamp):
        self.timestamp = timestamp
        self.start_time = time.monotonic()

    # Punch time is a future unix timestamp to start punching.
    def set_punch_time(self, punch_time):
        self.punch_time = punch_time

    def sleep_until(self):
        # Time elapsed in seconds since first starting.
        elapsed = time.monotonic() - self.start_time

        # Calculate a current unix timestamp based on elapsed.
        elapsed_abs = self.timestamp + int(elapsed)

        # The sleep time is the remaining time to sleep for
        sleep_time = max(0, self.punch_time - elapsed_abs)
        
        # Limit max sleep if current host is far behind.
        if sleep_time > self.max_sleep:
            sleep_time = self.max_sleep

        print("sleep until = ", sleep_time)
            
        # No sleep needed if far behind.
        if sleep_time > 0:
            time.sleep(sleep_time)

    def add_port_allocator(self, f_port_alloc, n=16):
        port_allocs, reserved = f_port_alloc(self.timestamp, n=n)
        for port_alloc in port_allocs:
            is_unique = True
            for stored_port_alloc in self.port_allocs:
                if tuple(port_alloc) == tuple(stored_port_alloc):
                    is_unique = False
                    break

            if is_unique:
                self.port_allocs.append(port_alloc)

    # Return a socket (punched hole) on success.
    def run_engine(self, f_engine):
        print("in run engine runner")
        return f_engine(
            af=self.af,
            nic_id=self.nic_id,
            port_allocs=self.port_allocs,
            src_ip=self.src_ip,
            dest_ip=self.dest_ip,
            f_sleep_until=self.sleep_until,
            our_ip=self.our_ip
        )

if __name__ == "__main__":
    async def main():
        #from ....nic.interface import Interface
        #nic = await Interface()

        # Get the dest IP.
        parser = argparse.ArgumentParser(description="Test main punching algorithm")
        parser.add_argument(
            "--dest_ip",
            type=str,
            required=True,
            help="Dest IP to punch to"
        )
        parser.add_argument(
            "--src_ip",
            type=str,
            required=False,
            help="SRC IP to punch from"
        )
        parser.add_argument(
            "--nic_id",
            type=str,
            required=False,
            help="NIC ID of nic to send from"
        )
        args = parser.parse_args()
        punch = PunchClient(args.dest_ip, args.src_ip, nic_id=args.nic_id)
        try:
            # Get unix timestamp from NTP.
            timestamp = timestamp_from_ntp()
            punch.set_timestamp(timestamp)

            # Calculate a future timestamp to use as the punch time.
            _, punch_time = compute_rendezvous(timestamp)
            punch.set_punch_time(punch_time)
            print("future punch time = ", punch_time)
            print("Current ntp time = ", timestamp)
        except RuntimeError as e:
            print(f"CRITICAL ERROR: {e}")
            sys.exit(1)

        # Default uses deterministic ports from NTP boundaries.
        punch.add_port_allocator(boundary_port_alloc)
        #out = pickle.dumps(punch)
        #l = pickle.loads(out)
        #print(l)

        # New punching engine uses non-blocking selector events.
        sock = punch.run_engine(tcp_selector_punch_engine)
        print(sock)

    asyncio.run(main())

