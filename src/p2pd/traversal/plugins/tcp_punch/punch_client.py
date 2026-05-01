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

from typing import Any, Dict, Optional
import sys
import time
import argparse
import socket
import asyncio
from aionetiface import IP6, ip_norm, patch_connect_ip, log
from .boundary_alloc import boundary_port_alloc
from .tcp_punch_engine import tcp_selector_punch_engine
from .punch_utils import timestamp_from_ntp
from .boundary_lib import DEFAULT_PUNCH_PARAMS, compute_rendezvous


# TODO: Could even use ARP to find the other node in a LAN
# running the same tool so the dest IP doesn't have to be specified.
class PunchClient:
    """Coordinates TCP hole-punching between two peers including port allocation and timing."""

    def __init__(
self,
        dest_ip: str,
        src_ip: Optional[str] = None,
        our_ip: Optional[str] = None,
        nic_id: Optional[str] = None,
        max_sleep: int = 10,
        same_machine: bool = False,
        params: Optional[Dict[str, Any]] = None,
    ) -> None:
        # Fallback to IP4
        self.af = socket.AF_INET
        if ":" in dest_ip:
            self.af = socket.AF_INET6

        # Fallback to default interface.
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.our_ip = our_ip
        self.same_machine = same_machine

        # NIC ID = name of a NIC or its number.
        # The value is needed mostly for IPv6.
        self.nic_id = nic_id
        if not nic_id and src_ip:
            # Try to extract the idea from % part of src_ip
            # if its found of course.
            if self.af == IP6 and "%" in src_ip:
                self.nic_id = src_ip.split("%")[1]

        # Listen bind / dest connect matrixes.
        self.port_allocs = []  # [ src bind, dest port ]

        # The allocator has to decide on this.
        # Relative time from start_time bellow.
        self.punch_time = 0

        # Default to inaccurate system clock.
        self.timestamp = int(time.time())
        self.start_time = time.monotonic()

        # Build the effective params dict.
        # If params is provided it takes priority; otherwise build from
        # DEFAULT_PUNCH_PARAMS with the legacy max_sleep kwarg applied so
        # that existing callers (tests, CLI) that pass max_sleep= directly
        # continue to work without change.
        if params is not None:
            self.params = params
        else:
            self.params = dict(DEFAULT_PUNCH_PARAMS)
            self.params["max_sleep"] = max_sleep

        self.max_sleep = self.params["max_sleep"]

        # Normalise all ips.
        # This strips all cidrs, $ stuff etc.
        self.dest_ip = ip_norm(self.dest_ip)
        if self.src_ip:
            self.src_ip = ip_norm(self.src_ip)
        if self.our_ip:
            self.our_ip = ip_norm(self.our_ip)

        # Patch dest IP based on special bind rules.
        self.dest_ip = patch_connect_ip(self.af, self.dest_ip, self.nic_id)

    def set_src_ip(self, src_ip: str) -> None:
        """Override the source IP address used when binding punch sockets."""
        self.src_ip = src_ip

    # Timestamp is a unix timestamp.
    def set_timestamp(self, timestamp: int) -> None:
        """Record the NTP-synchronised Unix timestamp as the clock reference for this punch."""
        wall = int(time.time())
        log("[PUNCH-CLIENT] set_timestamp ntp={0} wall={1} delta={2}s".format(
            timestamp, wall, wall - timestamp,
        ))
        self.timestamp = timestamp
        self.start_time = time.monotonic()

    # Punch time is a future unix timestamp to start punching.
    def set_punch_time(self, punch_time: int) -> None:
        """Set the future Unix timestamp at which both peers will simultaneously send SYNs."""
        wait = punch_time - getattr(self, "timestamp", punch_time)
        log("[PUNCH-CLIENT] set_punch_time={0} wait_from_ts={1}s".format(
            punch_time, wait,
        ))
        self.punch_time = punch_time

    def sleep_until(self) -> None:
        """Block the calling thread until the punch time is reached, capped by max_sleep."""
        # Time elapsed in seconds since first starting.
        elapsed = time.monotonic() - self.start_time

        # Calculate a current unix timestamp based on elapsed.
        elapsed_abs = self.timestamp + int(elapsed)

        # The sleep time is the remaining time to sleep for
        sleep_time = max(0, self.punch_time - elapsed_abs)

        capped = False
        # Limit max sleep if current host is far behind.
        if sleep_time > self.max_sleep:
            log("[PUNCH-CLIENT] sleep_until cap fired: requested={0}s "
                "max_sleep={1}s -- punch may fire before peer is ready".format(
                    sleep_time, self.max_sleep,
                ))
            sleep_time = self.max_sleep
            capped = True

        log("[PUNCH-CLIENT] sleep_until: ts={0} punch_time={1} sleep={2}s "
            "capped={3}".format(
                self.timestamp, self.punch_time, sleep_time, capped,
            ))

        # No sleep needed if far behind.
        if sleep_time > 0:
            # Heartbeat every 10 s for long waits so a stuck-here case
            # is distinguishable from a normal long wait. The actual
            # wall-clock fire still happens at the requested sleep_time.
            remaining = sleep_time
            while remaining > 0:
                step = min(10, remaining)
                time.sleep(step)
                remaining -= step
                if remaining > 0:
                    log("[PUNCH-CLIENT] sleep_until heartbeat: {0}s left".format(
                        int(remaining),
                    ))

    def add_port_allocator(self, f_port_alloc: Any, n: Optional[int] = None) -> None:
        """Run a port-allocation function and append unique PortAlloc entries to the list.

        n=None defers to the allocator's own default (boundary_port_alloc
        uses NUM_PORTS, which db0c676 lowered from 16 to 2 for the
        "smaller / wider port pool" tcp_punch tuning). The previous
        hard-coded default of 16 was overriding that intent on every
        call site -- the matrix had been running with 16-port sprays
        since db0c676 landed.
        """
        if n is None:
            port_allocs, reserved = f_port_alloc(self.timestamp, params=self.params)
        else:
            port_allocs, reserved = f_port_alloc(self.timestamp, n=n, params=self.params)
        for port_alloc in port_allocs:
            is_unique = True
            for stored_port_alloc in self.port_allocs:
                if tuple(port_alloc) == tuple(stored_port_alloc):
                    is_unique = False
                    break

            if is_unique:
                self.port_allocs.append(port_alloc)

    # Return a socket (punched hole) on success.
    def run_engine(self, f_engine: Any) -> Optional[Any]:
        """Execute the given punch engine function with this client's configuration and return the result socket."""
        return f_engine(
            af=self.af,
            nic_id=self.nic_id,
            port_allocs=self.port_allocs,
            src_ip=self.src_ip,
            dest_ip=self.dest_ip,
            f_sleep_until=self.sleep_until,
            our_ip=self.our_ip,
            same_machine=self.same_machine,
            params=self.params,
        )


if __name__ == "__main__":

    async def main():
        """Run a standalone punch test from the command line."""
        # from ....nic.interface import Interface
        # nic = await Interface()

        # Get the dest IP.
        parser = argparse.ArgumentParser(description="Test main punching algorithm")
        parser.add_argument(
            "--dest_ip", type=str, required=True, help="Dest IP to punch to"
        )
        parser.add_argument(
            "--src_ip", type=str, required=False, help="SRC IP to punch from"
        )
        parser.add_argument(
            "--nic_id", type=str, required=False, help="NIC ID of nic to send from"
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
            print("CRITICAL ERROR: ", e)
            sys.exit(1)

        # Default uses deterministic ports from NTP boundaries.
        punch.add_port_allocator(boundary_port_alloc)
        # out = pickle.dumps(punch)
        # l = pickle.loads(out)
        # print(l)

        # New punching engine uses non-blocking selector events.
        sock = punch.run_engine(tcp_selector_punch_engine)
        #print(sock)

    asyncio.run(main())
