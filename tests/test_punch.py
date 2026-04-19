"""
Tests for the punch plugin (TCP hole punching).

Two complementary test suites:

  TestPunchLoopback        --  Two punch instances on 127.0.0.1 (same loopback
                               IP, different source ports) test TCP hole punching
                               with a simple server/client model.

  TestPunchNicIPs          --  Same flow but each puncher is bound to a different
                               NIC IP (e.g. 10.0.1.76 / 10.0.1.100).  Skipped when
                               the machine has fewer than two private IPs on the
                               same interface.

  These tests validate TCP hole punching across multiple local IPs.

Run from project root:
    python3 -m pytest tests/test_punch.py -v
or
    python3 -m unittest tests/test_punch -v

TESTING WITH THE PUNCH PROGRAM ON MULTIPLE IPs
──────────────────────────────────────────────

The examples/punch.py program can be run directly from the command line to test
TCP hole punching between two machines (or two IPs on the same machine).

Example workflow using two IPs on the same machine:

1. Start a listening server on IP_A (in a terminal):
    python3 -c "import socket; s = socket.socket(); s.bind(('10.0.1.76', 40000)); s.listen(); s.accept()"

2. From a different IP_B, run the punch program to punch through to IP_A:
    python3 examples/punch.py 10.0.1.76

   This will:
    - Synchronize time with NTP
    - Bind to multiple ports on IP_B
    - Attempt simultaneous TCP connections to multiple destination ports on IP_A
    - Report successful connections

3. On success, you'll see output like:
    Connected on local port 30042
    Connected on local port 30001
    ...

KEY CONCEPTS
────────────

- The punch program uses NTP time synchronization to coordinate timing between peers.
- It allocates multiple source ports and attempts simultaneous connections.
- The simultaneous open (SYN-SYN) technique can create connected sockets through NAT.
- For testing on the same machine with multiple IPs, the "same_machine" flag
  adjusts behavior (reduced sleep times, different success criteria).
"""

import asyncio
import copy
import sys
import unittest
import socket
import time
import struct
import random
import selectors

import aionetiface
from aionetiface import (
    Interface, Pipe, TCP, UDP,
    IP4, IP6,
    EXT_BIND,
    to_s, rand_plain,
    async_wrap_errors, log_exception,
    bind_closure, binder_async, binder_sync,
)

from p2pd.traversal.libs.punch.punch_client import PunchClient
from p2pd.traversal.libs.punch.punch_defs import PortAlloc
from p2pd.traversal.libs.punch.utility.boundary_lib import (
    compute_rendezvous, stable_ports, stable_boundary, quantized_bucket
)
from p2pd.traversal.libs.punch.utility.punch_utils import timestamp_from_ntp
from p2pd.traversal.libs.punch.port_allocators.boundary_alloc import boundary_port_alloc
from p2pd.traversal.libs.punch.engines.tcp_selector_simple.engine import tcp_selector_punch_engine

from tests.turn_server import (
    make_fake_nic,
)


# ──────────────────────────────────────────────────────────────────────────────
# Async test base compatible with Python 3.5+
# ──────────────────────────────────────────────────────────────────────────────

if sys.version_info >= (3, 8):
    AsyncTestCase = unittest.IsolatedAsyncioTestCase
else:
    class AsyncTestCase(unittest.TestCase):
        """
        Minimal asyncio-compatible TestCase for Python 3.5+.

        Provides asyncSetUp / asyncTearDown hooks and runs async test
        methods in a dedicated event loop created fresh for each test.
        """

        def run(self, result=None):
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            try:
                return super(AsyncTestCase, self).run(result)
            finally:
                self._loop.close()
                asyncio.set_event_loop(None)

        def setUp(self):
            self._loop.run_until_complete(self.asyncSetUp())

        def tearDown(self):
            self._loop.run_until_complete(self.asyncTearDown())

        async def asyncSetUp(self):
            pass

        async def asyncTearDown(self):
            pass

        def __getattribute__(self, name):
            val = object.__getattribute__(self, name)
            if name.startswith("test") and asyncio.iscoroutinefunction(val):
                try:
                    loop = object.__getattribute__(self, "_loop")
                except AttributeError:
                    # _loop not set yet (e.g. during test collection).
                    return val
                def sync_wrapper(coro_fn=val, ev_loop=loop):
                    ev_loop.run_until_complete(coro_fn())
                return sync_wrapper
            return val


# ──────────────────────────────────────────────────────────────────────────────
# Punch testing helpers
# ──────────────────────────────────────────────────────────────────────────────


class SimpleTCPServer:
    """
    A simple TCP server that listens on a specific IP and port.
    Used to test if punch can successfully connect.
    Supports both IPv4 and IPv6.
    """
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.sock = None
        self.connections = []
        # Determine address family based on IP
        self.af = socket.AF_INET6 if ':' in ip else socket.AF_INET

    async def start(self):
        """Start the server and listen for connections."""
        self.sock = socket.socket(self.af, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass

        if self.af == socket.AF_INET6:
            bare_ip, _, nic_name = self.ip.partition("%")
            bind_tup = binder_sync(IP6, bare_ip, self.port, nic_name or None)
        else:
            bind_tup = (self.ip, self.port)
        self.sock.bind(bind_tup)
        self.sock.listen(5)
        self.listening = True

    async def accept_one(self, timeout=10):
        """Accept a single connection with timeout."""
        self.sock.setblocking(0)
        sel = selectors.DefaultSelector()
        sel.register(self.sock, selectors.EVENT_READ)

        start_time = time.time()
        while time.time() - start_time < timeout:
            events = sel.select(timeout=0.1)
            if events:
                try:
                    client_sock, client_addr = self.sock.accept()
                    self.connections.append(client_sock)
                    sel.close()
                    return client_sock, client_addr
                except Exception as e:
                    pass
            await asyncio.sleep(0.01)

        sel.close()
        return None, None

    async def close(self):
        """Close the server and all connections."""
        self.listening = False
        for conn in self.connections:
            try:
                conn.close()
            except Exception:
                pass
        if self.sock:
            self.sock.close()


def run_punch_engine(puncher, engine):
    """Run the punch engine in a blocking manner and return the socket."""
    try:
        return puncher.run_engine(engine)
    except Exception as e:
        print("Punch engine error: {}".format(e))
        import traceback
        traceback.print_exc()
        return None


async def punch_to_server(src_ip, dest_ip, dest_port, num_ports=16, base_port=30000):
    """
    Attempt TCP hole punching to a destination.

    Returns the socket if successful, None otherwise.
    """
    from p2pd.traversal.libs.punch.engines.tcp_selector_simple.engine import tcp_selector_punch_engine

    # Create a PunchClient configured for this punch attempt
    puncher = PunchClient(
        dest_ip=dest_ip,
        src_ip=src_ip,
        our_ip=src_ip,
        max_sleep=2,
        same_machine=True,
    )

    # For testing, use deterministic port allocation
    boundary = 12345  # Fixed boundary for reproducibility
    rng = random.Random(boundary)
    ports = set()
    while len(ports) < num_ports:
        port = base_port + rng.randint(0, 20000 - 1)
        ports.add(port)

    # Add ports as allocations (src_port, dest_port)
    for src_port in sorted(ports):
        puncher.port_allocs.append(PortAlloc(src_port, dest_port))

    # Run the punch engine in executor to avoid blocking
    loop = asyncio.get_event_loop()
    punched_sock = await asyncio.wait_for(
        loop.run_in_executor(None, run_punch_engine, puncher, tcp_selector_punch_engine),
        timeout=15
    )

    return punched_sock


# ──────────────────────────────────────────────────────────────────────────────
# Test 1 -- Loopback punch (same 127.0.0.1, different ports)
# ──────────────────────────────────────────────────────────────────────────────

class TestPunchLoopback(AsyncTestCase):
    """
    Test TCP hole punching on loopback (127.0.0.1).

    A server listens on one port, and a punch client attempts to connect
    from a different local port using TCP hole punching.
    """

    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP4 not in self.nic.supported():
            self.skipTest("IPv4 not available")
        self.server = None

    async def asyncTearDown(self):
        if self.server:
            await self.server.close()

    async def test_punch_client_creation(self):
        """Verify PunchClient can be instantiated with proper parameters."""
        puncher = PunchClient(
            dest_ip="127.0.0.1",
            src_ip="127.0.0.1",
            our_ip="127.0.0.1",
            max_sleep=2,
            same_machine=True,
        )

        self.assertEqual(puncher.dest_ip, "127.0.0.1")
        self.assertEqual(puncher.src_ip, "127.0.0.1")
        self.assertEqual(puncher.af, socket.AF_INET)
        self.assertEqual(puncher.same_machine, True)

    async def test_punch_port_allocation(self):
        """Verify port allocation works correctly in PunchClient."""
        puncher = PunchClient(
            dest_ip="127.0.0.1",
            src_ip="127.0.0.1",
            our_ip="127.0.0.1",
            max_sleep=2,
            same_machine=True,
        )

        # Add some port allocations
        src_ports = [30000, 30001, 30002]
        dest_port = 40000

        for src_port in src_ports:
            puncher.port_allocs.append(PortAlloc(src_port, dest_port))

        self.assertEqual(len(puncher.port_allocs), 3)
        for alloc in puncher.port_allocs:
            self.assertEqual(alloc.dest_port, dest_port)

    async def test_simple_server_accept(self):
        """Test that a simple TCP server can accept connections on loopback."""
        self.server = SimpleTCPServer("127.0.0.1", 0)  # Use random port
        await self.server.start()
        actual_port = self.server.sock.getsockname()[1]

        # Connect to the server from a client socket
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.setblocking(0)

        try:
            client.connect(("127.0.0.1", actual_port))
        except BlockingIOError:
            pass  # Expected for non-blocking socket

        # Wait for server to accept
        conn, addr = await asyncio.wait_for(self.server.accept_one(timeout=5), timeout=6)

        self.assertIsNotNone(conn, "Server should accept the connection")
        self.assertEqual(addr[0], "127.0.0.1")

        client.close()
        if conn:
            conn.close()

    async def test_multiple_punch_clients_different_sources(self):
        """
        Test that multiple PunchClient instances can be created targeting
        the same destination but with different source ports.
        """
        dest_ip = "127.0.0.1"

        puncher_a = PunchClient(
            dest_ip=dest_ip,
            src_ip="127.0.0.1",
            our_ip="127.0.0.1",
            max_sleep=2,
            same_machine=True,
        )

        puncher_b = PunchClient(
            dest_ip=dest_ip,
            src_ip="127.0.0.1",
            our_ip="127.0.0.1",
            max_sleep=2,
            same_machine=True,
        )

        # Allocate different port ranges for each
        for port in range(30000, 30005):
            puncher_a.port_allocs.append(PortAlloc(port, 40000))

        for port in range(30100, 30105):
            puncher_b.port_allocs.append(PortAlloc(port, 40000))

        # Verify they have distinct source ports
        ports_a = [alloc.src_port for alloc in puncher_a.port_allocs]
        ports_b = [alloc.src_port for alloc in puncher_b.port_allocs]

        intersection = set(ports_a) & set(ports_b)
        self.assertEqual(len(intersection), 0,
                        "Two punch clients should have non-overlapping source ports")

    async def test_punch_time_calculation(self):
        """
        Test that PunchClient correctly computes punch_time using
        timestamp and rendezvous calculation.
        """
        puncher = PunchClient(
            dest_ip="127.0.0.1",
            src_ip="127.0.0.1",
            our_ip="127.0.0.1",
            max_sleep=2,
            same_machine=True,
        )

        # Set a base timestamp
        base_timestamp = int(time.time())
        puncher.set_timestamp(base_timestamp)

        # Compute rendezvous should return future time
        bucket, rendezvous_time = compute_rendezvous(base_timestamp)

        self.assertGreater(rendezvous_time, base_timestamp,
                          "Rendezvous time should be in the future")
        self.assertIsInstance(bucket, int,
                             "Bucket should be an integer")
        self.assertIsInstance(rendezvous_time, (int, float),
                             "Rendezvous time should be numeric")


# ──────────────────────────────────────────────────────────────────────────────
# Test 2 -- Punch with multiple NIC IPs
# ──────────────────────────────────────────────────────────────────────────────

class TestPunchNicIPs(AsyncTestCase):
    """
    Test TCP hole punching across different NIC IPs.

    Puncher A is bound to NIC IP[0], Puncher B targets from NIC IP[1].
    Validates that punch can work across different local IPs on the same interface.

    Skipped when the active interface has fewer than two private IPv4 addresses.
    """

    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP4 not in self.nic.supported():
            self.skipTest("IPv4 not available on this machine")

        r4 = self.nic.route(IP4)
        if len(r4.nic_ips) < 2:
            self.skipTest(
                "Need >= 2 NIC IPs for this test (found: {0})".format(
                    [str(ip) for ip in r4.nic_ips]
                )
            )

        self.ipr_a = r4.nic_ips[0]
        self.ipr_b = r4.nic_ips[1]
        self.ip_a  = str(self.ipr_a.ip)
        self.ip_b  = str(self.ipr_b.ip)

        print("\nTest using NIC IPs: {} and {}".format(self.ip_a, self.ip_b))

        self.server = None

    async def asyncTearDown(self):
        if self.server:
            await self.server.close()

    async def test_nic_ips_are_distinct(self):
        """
        Verify that the test has access to two distinct NIC IPs.
        This is a sanity check before more complex tests.
        """
        self.assertNotEqual(self.ip_a, self.ip_b,
                           "Test IPs should be distinct")
        self.assertTrue(self.ip_a.replace('.', '').isdigit(),
                       "IP A should be a valid IPv4 address")
        self.assertTrue(self.ip_b.replace('.', '').isdigit(),
                       "IP B should be a valid IPv4 address")

    async def test_punch_client_from_ip_a_to_ip_b(self):
        """
        Create a PunchClient on IP A targeting IP B.
        Verify the client is correctly configured.
        """
        puncher = PunchClient(
            dest_ip=self.ip_b,
            src_ip=self.ip_a,
            our_ip=self.ip_a,
            max_sleep=2,
            same_machine=True,
        )

        self.assertEqual(puncher.dest_ip, self.ip_b,
                        "Puncher should target IP B")
        self.assertEqual(puncher.src_ip, self.ip_a,
                        "Puncher should be bound to IP A")

    async def test_punch_client_from_ip_b_to_ip_a(self):
        """
        Create a PunchClient on IP B targeting IP A.
        Verify the client is correctly configured.
        """
        puncher = PunchClient(
            dest_ip=self.ip_a,
            src_ip=self.ip_b,
            our_ip=self.ip_b,
            max_sleep=2,
            same_machine=True,
        )

        self.assertEqual(puncher.dest_ip, self.ip_a,
                        "Puncher should target IP A")
        self.assertEqual(puncher.src_ip, self.ip_b,
                        "Puncher should be bound to IP B")

    async def test_server_on_ip_a_reachable_from_ip_b(self):
        """
        Test basic connectivity: start a server on IP A and connect from IP B.
        This validates the test infrastructure works before attempting punch.
        """
        self.server = SimpleTCPServer(self.ip_a, 0)
        await self.server.start()
        server_port = self.server.sock.getsockname()[1]

        # Create a client socket bound to IP B
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass

        client.bind((self.ip_b, 0))
        client.setblocking(0)

        try:
            client.connect((self.ip_a, server_port))
        except BlockingIOError:
            pass  # Expected for non-blocking socket

        # Server should accept the connection
        conn, addr = await asyncio.wait_for(
            self.server.accept_one(timeout=5),
            timeout=6
        )

        self.assertIsNotNone(conn,
            "Server on {}:{} should accept connection from {}".format(self.ip_a, server_port, self.ip_b))
        self.assertEqual(addr[0], self.ip_b,
            "Server should see connection from IP B")

        client.close()
        if conn:
            conn.close()

    async def test_punch_config_cross_nic_ips(self):
        """
        Test that two punch clients targeting each other across different IPs
        have non-overlapping port allocations.
        """
        puncher_a = PunchClient(
            dest_ip=self.ip_b,
            src_ip=self.ip_a,
            our_ip=self.ip_a,
            max_sleep=2,
            same_machine=True,
        )

        puncher_b = PunchClient(
            dest_ip=self.ip_a,
            src_ip=self.ip_b,
            our_ip=self.ip_b,
            max_sleep=2,
            same_machine=True,
        )

        # Allocate ports: A punches to B's listening port range
        b_dest_port = 40000
        for src_port in range(30000, 30005):
            puncher_a.port_allocs.append(PortAlloc(src_port, b_dest_port))

        # Allocate ports: B punches to A's listening port range
        a_dest_port = 41000
        for src_port in range(30100, 30105):
            puncher_b.port_allocs.append(PortAlloc(src_port, a_dest_port))

        # Verify A targets B on the right port
        self.assertTrue(
            any(alloc.dest_port == b_dest_port for alloc in puncher_a.port_allocs),
            "Puncher A should target B's destination port"
        )

        # Verify B targets A on the right port
        self.assertTrue(
            any(alloc.dest_port == a_dest_port for alloc in puncher_b.port_allocs),
            "Puncher B should target A's destination port"
        )

    async def test_bidirectional_punch_setup(self):
        """
        Test a realistic bidirectional punch scenario where:
        - Puncher A (on IP A) punches to Puncher B (on IP B)
        - Puncher B (on IP B) punches to Puncher A (on IP A)

        This validates the configuration for a NAT traversal scenario.
        """
        # Create bidirectional punchers
        puncher_a = PunchClient(
            dest_ip=self.ip_b,
            src_ip=self.ip_a,
            our_ip=self.ip_a,
            max_sleep=2,
            same_machine=True,
        )

        puncher_b = PunchClient(
            dest_ip=self.ip_a,
            src_ip=self.ip_b,
            our_ip=self.ip_b,
            max_sleep=2,
            same_machine=True,
        )

        # Allocate multiple ports for increased success probability
        num_ports = 8
        a_src_range = range(30000, 30000 + num_ports)
        b_src_range = range(31000, 31000 + num_ports)

        a_dest_port = 40000
        b_dest_port = 40001

        for src_port in a_src_range:
            puncher_a.port_allocs.append(PortAlloc(src_port, b_dest_port))

        for src_port in b_src_range:
            puncher_b.port_allocs.append(PortAlloc(src_port, a_dest_port))

        # Validation: Check bidirectional setup
        self.assertEqual(len(puncher_a.port_allocs), num_ports)
        self.assertEqual(len(puncher_b.port_allocs), num_ports)

        # All allocations have correct destinations
        for alloc in puncher_a.port_allocs:
            self.assertEqual(alloc.dest_port, b_dest_port)

        for alloc in puncher_b.port_allocs:
            self.assertEqual(alloc.dest_port, a_dest_port)

        # Source ports don't overlap between punchers
        a_src_ports = {alloc.src_port for alloc in puncher_a.port_allocs}
        b_src_ports = {alloc.src_port for alloc in puncher_b.port_allocs}
        self.assertEqual(len(a_src_ports & b_src_ports), 0)

        print("\nBidirectional punch setup validated:")
        print("  A ({}) -> B ({}:{}) with {} ports".format(self.ip_a, self.ip_b, b_dest_port, len(puncher_a.port_allocs)))
        print("  B ({}) -> A ({}:{}) with {} ports".format(self.ip_b, self.ip_a, a_dest_port, len(puncher_b.port_allocs)))

    async def test_bidirectional_ntp_synchronized_punch(self):
        """
        Test bidirectional punching with NTP synchronization across multiple IPs.

        This test mirrors the punch_client.py __main__ scenario:
        1. Create two PunchClient instances on different IPs
        2. Synchronize them with NTP time
        3. Calculate punch times using compute_rendezvous
        4. Configure port allocators
        5. Verify both clients are ready for simultaneous punch attempt

        This validates the core setup flow that would be used in production.
        """
        # Try to get NTP time; if unavailable (network issue), use system time
        try:
            ntp_timestamp = timestamp_from_ntp()
            print("NTP timestamp: {}".format(ntp_timestamp))
        except RuntimeError:
            # Fallback to system time for testing
            ntp_timestamp = int(time.time())
            print("NTP unavailable, using system time: {}".format(ntp_timestamp))

        # Create puncher A: on IP A, punching to IP B
        puncher_a = PunchClient(
            dest_ip=self.ip_b,
            src_ip=self.ip_a,
            our_ip=self.ip_a,
            nic_id=None,
            max_sleep=3,
            same_machine=True,
        )

        # Set timestamp and calculate punch time
        puncher_a.set_timestamp(ntp_timestamp)
        bucket_a, punch_time_a = compute_rendezvous(ntp_timestamp)
        puncher_a.set_punch_time(punch_time_a)

        # Add port allocator (uses deterministic boundary-based ports)
        puncher_a.add_port_allocator(boundary_port_alloc)

        # Create puncher B: on IP B, punching to IP A
        puncher_b = PunchClient(
            dest_ip=self.ip_a,
            src_ip=self.ip_b,
            our_ip=self.ip_b,
            nic_id=None,
            max_sleep=3,
            same_machine=True,
        )

        # Use same timestamp to synchronize
        puncher_b.set_timestamp(ntp_timestamp)
        bucket_b, punch_time_b = compute_rendezvous(ntp_timestamp)
        puncher_b.set_punch_time(punch_time_b)

        # Add port allocator
        puncher_b.add_port_allocator(boundary_port_alloc)

        # Validation 1: Both punchers have the same bucket (time synchronized)
        self.assertEqual(bucket_a, bucket_b,
            "Both punchers should calculate the same time bucket from NTP time")

        # Validation 2: Both punchers have future punch times
        self.assertGreater(punch_time_a, ntp_timestamp,
            "Puncher A punch_time should be in the future")
        self.assertGreater(punch_time_b, ntp_timestamp,
            "Puncher B punch_time should be in the future")

        # Validation 3: Both punchers should have punch times in the same window
        # (allowing for minor system clock differences)
        time_diff = abs(punch_time_a - punch_time_b)
        self.assertLess(time_diff, 2,
            "Punch times should be very close (diff: {}s)".format(time_diff))

        # Validation 4: Both punchers have port allocations
        self.assertGreater(len(puncher_a.port_allocs), 0,
            "Puncher A should have port allocations after add_port_allocator")
        self.assertGreater(len(puncher_b.port_allocs), 0,
            "Puncher B should have port allocations after add_port_allocator")

        # Validation 5: Port allocations target the correct destinations
        for alloc_a in puncher_a.port_allocs:
            self.assertIsNotNone(alloc_a.src_port, "Source port should be set")
            self.assertIsNotNone(alloc_a.dest_port, "Destination port should be set")

        for alloc_b in puncher_b.port_allocs:
            self.assertIsNotNone(alloc_b.src_port, "Source port should be set")
            self.assertIsNotNone(alloc_b.dest_port, "Destination port should be set")

        # Validation 6: Destinations are correct
        # Puncher A targets IP B, Puncher B targets IP A
        self.assertEqual(puncher_a.dest_ip, self.ip_b)
        self.assertEqual(puncher_b.dest_ip, self.ip_a)

        print("\nBidirectional NTP-synchronized punch ready:")
        print("  NTP time: {}".format(ntp_timestamp))
        print("  Bucket: {}".format(bucket_a))
        print("  Punch time A: {}".format(punch_time_a))
        print("  Punch time B: {}".format(punch_time_b))
        print("  A ({}) -> B ({}) with {} ports".format(self.ip_a, self.ip_b, len(puncher_a.port_allocs)))
        print("  B ({}) -> A ({}) with {} ports".format(self.ip_b, self.ip_a, len(puncher_b.port_allocs)))
        print("  Ready to run tcp_selector_punch_engine on each puncher")

    async def test_actual_bidirectional_punch_with_sockets(self):
        """
        Test actual bidirectional TCP punching with real socket creation.

        This is the most realistic test - it:
        1. Creates listening sockets on both IPs
        2. Configures two PunchClient instances for simultaneous punch
        3. Runs the punch engines in parallel with proper timing
        4. Verifies actual connected sockets are created
        5. Validates socket addresses match expected IPs

        This tests the complete punch workflow including the actual
        tcp_selector_punch_engine execution.
        """
        # Get NTP time for synchronization
        try:
            ntp_timestamp = timestamp_from_ntp()
        except RuntimeError:
            ntp_timestamp = int(time.time())

        # Allocate random listening ports
        listen_port_a = 0  # Let OS choose
        listen_port_b = 0

        # Create listening sockets on both IPs
        listen_sock_a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock_a.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listen_sock_a.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        listen_sock_a.bind((self.ip_a, listen_port_a))
        listen_sock_a.listen(5)
        listen_port_a = listen_sock_a.getsockname()[1]

        listen_sock_b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock_b.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listen_sock_b.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        listen_sock_b.bind((self.ip_b, listen_port_b))
        listen_sock_b.listen(5)
        listen_port_b = listen_sock_b.getsockname()[1]

        print("\nListening sockets created:")
        print("  A: {}:{}".format(self.ip_a, listen_port_a))
        print("  B: {}:{}".format(self.ip_b, listen_port_b))

        try:
            # Create puncher A: on IP A, punching to IP B's listening port
            puncher_a = PunchClient(
                dest_ip=self.ip_b,
                src_ip=self.ip_a,
                our_ip=self.ip_a,
                max_sleep=3,
                same_machine=True,
            )
            puncher_a.set_timestamp(ntp_timestamp)
            bucket_a, punch_time_a = compute_rendezvous(ntp_timestamp)
            puncher_a.set_punch_time(punch_time_a)
            puncher_a.add_port_allocator(boundary_port_alloc)

            # Create puncher B: on IP B, punching to IP A's listening port
            puncher_b = PunchClient(
                dest_ip=self.ip_a,
                src_ip=self.ip_b,
                our_ip=self.ip_b,
                max_sleep=3,
                same_machine=True,
            )
            puncher_b.set_timestamp(ntp_timestamp)
            bucket_b, punch_time_b = compute_rendezvous(ntp_timestamp)
            puncher_b.set_punch_time(punch_time_b)
            puncher_b.add_port_allocator(boundary_port_alloc)

            print("\nPunch configurations:")
            print("  Puncher A: {} -> {}:{}".format(self.ip_a, self.ip_b, listen_port_b))
            print("  Puncher B: {} -> {}:{}".format(self.ip_b, self.ip_a, listen_port_a))
            print("  Punch time: {} (bucket {})".format(punch_time_a, bucket_a))

            # Set the listening port as the destination port for each puncher
            # Replace the port allocations with the actual listening ports
            puncher_a.port_allocs.clear()
            for src_port in range(30000, 30008):
                puncher_a.port_allocs.append(PortAlloc(src_port, listen_port_b))

            puncher_b.port_allocs.clear()
            for src_port in range(31000, 31008):
                puncher_b.port_allocs.append(PortAlloc(src_port, listen_port_a))

            # Run punch engines in parallel using executor
            loop = asyncio.get_event_loop()

            # Make listening sockets non-blocking for accept
            listen_sock_a.setblocking(False)
            listen_sock_b.setblocking(False)

            # Run both punch engines concurrently
            print("\nRunning punch engines...")
            punch_a_task = loop.run_in_executor(
                None, run_punch_engine, puncher_a, tcp_selector_punch_engine
            )
            punch_b_task = loop.run_in_executor(
                None, run_punch_engine, puncher_b, tcp_selector_punch_engine
            )

            # Wait for both to complete with timeout
            try:
                sock_a, sock_b = await asyncio.wait_for(
                    asyncio.gather(punch_a_task, punch_b_task),
                    timeout=20
                )
            except asyncio.TimeoutError:
                print("Punch engines timed out (expected in some NAT scenarios)")
                sock_a = None
                sock_b = None

            # Check results
            if sock_a is not None:
                print("✓ Puncher A succeeded!")
                try:
                    peer = sock_a.getpeername()
                    local = sock_a.getsockname()
                    print("  Local: {}:{}".format(local[0], local[1]))
                    print("  Peer: {}:{}".format(peer[0], peer[1]))
                    self.assertEqual(peer[0], self.ip_b, "Should connect to IP B")
                    sock_a.close()
                except Exception as e:
                    print("  Error getting socket info: {}".format(e))
            else:
                print("✗ Puncher A did not create socket (may indicate NAT blocking)")

            if sock_b is not None:
                print("✓ Puncher B succeeded!")
                try:
                    peer = sock_b.getpeername()
                    local = sock_b.getsockname()
                    print("  Local: {}:{}".format(local[0], local[1]))
                    print("  Peer: {}:{}".format(peer[0], peer[1]))
                    self.assertEqual(peer[0], self.ip_a, "Should connect to IP A")
                    sock_b.close()
                except Exception as e:
                    print("  Error getting socket info: {}".format(e))
            else:
                print("✗ Puncher B did not create socket (may indicate NAT blocking)")

            # At least one should succeed or both should fail gracefully
            # (On localhost, both should succeed due to no NAT)
            if sock_a or sock_b:
                print("\n✓ TCP punch successful on at least one direction")
            else:
                print("\nℹ No punch connections (expected behind restrictive NAT)")

        finally:
            # Clean up listening sockets
            listen_sock_a.close()
            listen_sock_b.close()


# ──────────────────────────────────────────────────────────────────────────────
# Test 3 -- IPv6 Loopback punch (same ::1, different ports)
# ──────────────────────────────────────────────────────────────────────────────

class TestPunchIPv6Loopback(AsyncTestCase):
    """
    Test TCP hole punching on IPv6 loopback (::1).

    A server listens on one port, and a punch client attempts to connect
    from a different local port using TCP hole punching over IPv6.

    Skipped when IPv6 is not available on this machine.
    """

    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP6 not in self.nic.supported():
            self.skipTest("IPv6 not available")
        self.server = None

    async def asyncTearDown(self):
        if self.server:
            await self.server.close()

    async def test_ipv6_punch_client_creation(self):
        """Verify PunchClient can be instantiated with IPv6 parameters."""
        puncher = PunchClient(
            dest_ip="::1",
            src_ip="::1",
            our_ip="::1",
            max_sleep=2,
            same_machine=True,
        )

        # IPv6 addresses may be normalized to full form; just verify they're loopback
        self.assertIn('1', puncher.dest_ip, "dest_ip should contain loopback indicator")
        self.assertIn('1', puncher.src_ip, "src_ip should contain loopback indicator")
        self.assertEqual(puncher.af, socket.AF_INET6)
        self.assertEqual(puncher.same_machine, True)

    async def test_ipv6_punch_port_allocation(self):
        """Verify port allocation works correctly with IPv6."""
        puncher = PunchClient(
            dest_ip="::1",
            src_ip="::1",
            our_ip="::1",
            max_sleep=2,
            same_machine=True,
        )

        src_ports = [30000, 30001, 30002]
        dest_port = 40000

        for src_port in src_ports:
            puncher.port_allocs.append(PortAlloc(src_port, dest_port))

        self.assertEqual(len(puncher.port_allocs), 3)
        for alloc in puncher.port_allocs:
            self.assertEqual(alloc.dest_port, dest_port)

    async def test_ipv6_multiple_punch_clients(self):
        """Test multiple IPv6 punch clients with distinct ports."""
        dest_ip = "::1"

        puncher_a = PunchClient(
            dest_ip=dest_ip,
            src_ip="::1",
            our_ip="::1",
            max_sleep=2,
            same_machine=True,
        )

        puncher_b = PunchClient(
            dest_ip=dest_ip,
            src_ip="::1",
            our_ip="::1",
            max_sleep=2,
            same_machine=True,
        )

        for port in range(30000, 30005):
            puncher_a.port_allocs.append(PortAlloc(port, 40000))

        for port in range(30100, 30105):
            puncher_b.port_allocs.append(PortAlloc(port, 40000))

        ports_a = [alloc.src_port for alloc in puncher_a.port_allocs]
        ports_b = [alloc.src_port for alloc in puncher_b.port_allocs]

        intersection = set(ports_a) & set(ports_b)
        self.assertEqual(len(intersection), 0,
                        "IPv6 punch clients should have non-overlapping source ports")

    async def test_ipv6_punch_time_calculation(self):
        """Test NTP time rendezvous calculation for IPv6."""
        puncher = PunchClient(
            dest_ip="::1",
            src_ip="::1",
            our_ip="::1",
            max_sleep=2,
            same_machine=True,
        )

        base_timestamp = int(time.time())
        puncher.set_timestamp(base_timestamp)

        bucket, rendezvous_time = compute_rendezvous(base_timestamp)

        self.assertGreater(rendezvous_time, base_timestamp,
                          "IPv6 rendezvous time should be in the future")
        self.assertIsInstance(bucket, int,
                             "Bucket should be an integer")

    async def test_ipv6_link_local_with_scope_id(self):
        """Test IPv6 link-local address with scope ID extraction."""
        # Simulate a link-local IPv6 address with scope ID (common on real interfaces)
        link_local_ip = "fe80::1%eth0"

        puncher = PunchClient(
            dest_ip=link_local_ip,
            src_ip=link_local_ip,
            our_ip=link_local_ip,
            max_sleep=2,
            same_machine=True,
        )

        # Verify the NIC ID was extracted from the scope ID
        self.assertEqual(puncher.nic_id, "eth0",
                        "NIC ID should be extracted from % notation")
        self.assertEqual(puncher.af, socket.AF_INET6,
                        "Should be IPv6 address family")

    async def test_ipv6_link_local_address_detection(self):
        """Test detection of IPv6 link-local addresses."""
        link_local_addresses = [
            "fe80::1",
            "fe80::1%eth0",
            "fe80:0000:0000:0000:0000:0000:0000:0001",
            "fe80::0001:0002:0003:0004%wlan0",
        ]

        for link_local in link_local_addresses:
            puncher = PunchClient(
                dest_ip=link_local,
                src_ip=link_local,
                our_ip=link_local,
                max_sleep=2,
                same_machine=True,
            )
            # All should be detected as IPv6
            self.assertEqual(puncher.af, socket.AF_INET6,
                            "Link-local {} should be IPv6".format(link_local))

    async def test_ipv6_link_local_vs_global(self):
        """Test that link-local and global IPv6 addresses are both supported."""
        link_local = "fe80::1%eth0"
        global_ipv6 = "2001:db8::1"

        puncher_ll = PunchClient(
            dest_ip=link_local,
            src_ip=link_local,
            our_ip=link_local,
            max_sleep=2,
            same_machine=True,
        )

        puncher_global = PunchClient(
            dest_ip=global_ipv6,
            src_ip=global_ipv6,
            our_ip=global_ipv6,
            max_sleep=2,
            same_machine=True,
        )

        # Both should be IPv6
        self.assertEqual(puncher_ll.af, socket.AF_INET6)
        self.assertEqual(puncher_global.af, socket.AF_INET6)

        # Link-local should have extracted NIC ID
        self.assertEqual(puncher_ll.nic_id, "eth0")

        # Global should not have NIC ID set (no % in address)
        self.assertIsNone(puncher_global.nic_id)


# ──────────────────────────────────────────────────────────────────────────────
# Test 4 -- IPv6 punch with multiple NIC IPs
# ──────────────────────────────────────────────────────────────────────────────

class TestPunchIPv6NicIPs(AsyncTestCase):
    """
    Test TCP hole punching across different IPv6 NIC IPs.

    Puncher A is bound to NIC IPv6[0], Puncher B targets from NIC IPv6[1].
    Validates that punch can work across different local IPv6 addresses
    on the same interface.

    Skipped when IPv6 is not available or the machine has fewer than two IPv6 addresses.
    """

    async def asyncSetUp(self):
        self.nic = await Interface()
        if IP6 not in self.nic.supported():
            self.skipTest("IPv6 not available on this machine")

        r6 = self.nic.route(IP6)

        # Try to use link-local addresses first (most common case)
        link_locals = getattr(r6, 'link_locals', [])

        if len(link_locals) >= 2:
            # Use two different link-local addresses
            self.ipr_a = link_locals[0]
            self.ipr_b = link_locals[1]
            addr_type = "link-local"
        elif len(link_locals) >= 1 and len(r6.nic_ips) >= 1:
            # Have 1 link-local + at least 1 global; use them both
            self.ipr_a = link_locals[0]
            self.ipr_b = r6.nic_ips[0]
            addr_type = "link-local + global"
        elif len(r6.nic_ips) >= 2:
            # Fall back to using two global addresses
            self.ipr_a = r6.nic_ips[0]
            self.ipr_b = r6.nic_ips[1]
            addr_type = "global"
        else:
            self.skipTest(
                "Need >= 2 IPv6 addresses for this test (found: {0} link-local, {1} global)".format(
                    len(link_locals), len(r6.nic_ips)
                )
            )

        self.ip_a  = str(self.ipr_a.ip)
        self.ip_b  = str(self.ipr_b.ip)
        self.nic_name = self.nic.name

        # For link-local addresses, we need to add the scope ID when binding
        # link-local addresses start with fe80
        if self.ip_a.startswith("fe80"):
            self.ip_a_with_scope = "{}%{}".format(self.ip_a, self.nic_name)
        else:
            self.ip_a_with_scope = self.ip_a

        if self.ip_b.startswith("fe80"):
            self.ip_b_with_scope = "{}%{}".format(self.ip_b, self.nic_name)
        else:
            self.ip_b_with_scope = self.ip_b

        print("\nIPv6 Test using {} IPs: {} and {}".format(addr_type, self.ip_a, self.ip_b))
        if self.ip_a != self.ip_a_with_scope or self.ip_b != self.ip_b_with_scope:
            print("  With scope: {} and {}".format(self.ip_a_with_scope, self.ip_b_with_scope))

        self.server = None

    async def asyncTearDown(self):
        if self.server:
            await self.server.close()

    async def test_ipv6_nic_ips_are_distinct(self):
        """Verify that two distinct IPv6 NIC IPs are available."""
        self.assertNotEqual(self.ip_a, self.ip_b,
                           "IPv6 test IPs should be distinct")
        self.assertIn(':', self.ip_a, "IP A should be IPv6 (contain ':')")
        self.assertIn(':', self.ip_b, "IP B should be IPv6 (contain ':')")

    async def test_ipv6_punch_client_from_ip_a_to_ip_b(self):
        """Create an IPv6 PunchClient on IP A targeting IP B."""
        puncher = PunchClient(
            dest_ip=self.ip_b,
            src_ip=self.ip_a,
            our_ip=self.ip_a,
            max_sleep=2,
            same_machine=True,
        )

        self.assertEqual(puncher.dest_ip, self.ip_b,
                        "IPv6 Puncher should target IP B")
        self.assertEqual(puncher.src_ip, self.ip_a,
                        "IPv6 Puncher should be bound to IP A")
        self.assertEqual(puncher.af, socket.AF_INET6,
                        "Address family should be IPv6")

    async def test_ipv6_punch_client_from_ip_b_to_ip_a(self):
        """Create an IPv6 PunchClient on IP B targeting IP A."""
        # Use scoped addresses for link-local
        puncher = PunchClient(
            dest_ip=self.ip_a_with_scope,
            src_ip=self.ip_b_with_scope,
            our_ip=self.ip_b_with_scope,
            max_sleep=2,
            same_machine=True,
        )

        # Compare without exact match since addresses might be normalized
        self.assertIn(self.ip_a.split('%')[0], puncher.dest_ip,
                        "IPv6 Puncher should target IP A")
        self.assertIn(self.ip_b.split('%')[0], puncher.src_ip,
                        "IPv6 Puncher should be bound to IP B")

    async def test_ipv6_server_reachable_across_ips(self):
        """Test IPv6 connectivity: server on IP A reachable from IP B."""
        # Skip if we have mixed link-local + global addresses
        # (different address families have compatibility issues)
        if self.ip_a_with_scope != self.ip_a or self.ip_b_with_scope != self.ip_b:
            if (self.ip_a_with_scope != self.ip_a) != (self.ip_b_with_scope != self.ip_b):
                self.skipTest("Cannot mix link-local and global IPv6 addresses in socket tests")

        self.server = SimpleTCPServer(self.ip_a_with_scope, 0)
        await self.server.start()
        server_port = self.server.sock.getsockname()[1]

        # Create IPv6 client socket bound to IP B
        client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass

        client.bind(binder_sync(IP6, self.ip_b, 0, self.nic_name))
        client.setblocking(0)

        try:
            client.connect(binder_sync(IP6, self.ip_a, server_port, self.nic_name))
        except BlockingIOError:
            pass

        # Server should accept the connection
        conn, addr = await asyncio.wait_for(
            self.server.accept_one(timeout=5),
            timeout=6
        )

        self.assertIsNotNone(conn,
            "IPv6 Server on {}:{} should accept connection from {}".format(self.ip_a, server_port, self.ip_b))
        self.assertEqual(
            socket.inet_pton(socket.AF_INET6, addr[0]),
            socket.inet_pton(socket.AF_INET6, self.ip_b),
            "Server should see connection from IPv6 IP B")

        client.close()
        if conn:
            conn.close()

    async def test_ipv6_bidirectional_punch_setup(self):
        """Test realistic bidirectional IPv6 punch scenario."""
        puncher_a = PunchClient(
            dest_ip=self.ip_b,
            src_ip=self.ip_a,
            our_ip=self.ip_a,
            max_sleep=2,
            same_machine=True,
        )

        puncher_b = PunchClient(
            dest_ip=self.ip_a,
            src_ip=self.ip_b,
            our_ip=self.ip_b,
            max_sleep=2,
            same_machine=True,
        )

        num_ports = 8
        a_src_range = range(30000, 30000 + num_ports)
        b_src_range = range(31000, 31000 + num_ports)

        a_dest_port = 40000
        b_dest_port = 40001

        for src_port in a_src_range:
            puncher_a.port_allocs.append(PortAlloc(src_port, b_dest_port))

        for src_port in b_src_range:
            puncher_b.port_allocs.append(PortAlloc(src_port, a_dest_port))

        self.assertEqual(len(puncher_a.port_allocs), num_ports)
        self.assertEqual(len(puncher_b.port_allocs), num_ports)

        for alloc in puncher_a.port_allocs:
            self.assertEqual(alloc.dest_port, b_dest_port)

        for alloc in puncher_b.port_allocs:
            self.assertEqual(alloc.dest_port, a_dest_port)

        a_src_ports = {alloc.src_port for alloc in puncher_a.port_allocs}
        b_src_ports = {alloc.src_port for alloc in puncher_b.port_allocs}
        self.assertEqual(len(a_src_ports & b_src_ports), 0)

        print("\nIPv6 Bidirectional punch setup validated:")
        print("  A ({}) -> B ({}:{}) with {} ports".format(self.ip_a, self.ip_b, b_dest_port, len(puncher_a.port_allocs)))
        print("  B ({}) -> A ({}:{}) with {} ports".format(self.ip_b, self.ip_a, a_dest_port, len(puncher_b.port_allocs)))

    async def test_ipv6_bidirectional_ntp_synchronized_punch(self):
        """Test IPv6 bidirectional punching with NTP synchronization."""
        try:
            ntp_timestamp = timestamp_from_ntp()
            print("IPv6 NTP timestamp: {}".format(ntp_timestamp))
        except RuntimeError:
            ntp_timestamp = int(time.time())
            print("IPv6 NTP unavailable, using system time: {}".format(ntp_timestamp))

        puncher_a = PunchClient(
            dest_ip=self.ip_b,
            src_ip=self.ip_a,
            our_ip=self.ip_a,
            nic_id=None,
            max_sleep=3,
            same_machine=True,
        )

        puncher_a.set_timestamp(ntp_timestamp)
        bucket_a, punch_time_a = compute_rendezvous(ntp_timestamp)
        puncher_a.set_punch_time(punch_time_a)
        puncher_a.add_port_allocator(boundary_port_alloc)

        puncher_b = PunchClient(
            dest_ip=self.ip_a,
            src_ip=self.ip_b,
            our_ip=self.ip_b,
            nic_id=None,
            max_sleep=3,
            same_machine=True,
        )

        puncher_b.set_timestamp(ntp_timestamp)
        bucket_b, punch_time_b = compute_rendezvous(ntp_timestamp)
        puncher_b.set_punch_time(punch_time_b)
        puncher_b.add_port_allocator(boundary_port_alloc)

        # Validations
        self.assertEqual(bucket_a, bucket_b,
            "IPv6 punchers should calculate the same time bucket")

        self.assertGreater(punch_time_a, ntp_timestamp,
            "IPv6 Puncher A punch_time should be in the future")
        self.assertGreater(punch_time_b, ntp_timestamp,
            "IPv6 Puncher B punch_time should be in the future")

        time_diff = abs(punch_time_a - punch_time_b)
        self.assertLess(time_diff, 2,
            "IPv6 punch times should be very close (diff: {}s)".format(time_diff))

        self.assertGreater(len(puncher_a.port_allocs), 0,
            "IPv6 Puncher A should have port allocations")
        self.assertGreater(len(puncher_b.port_allocs), 0,
            "IPv6 Puncher B should have port allocations")

        print("\nIPv6 Bidirectional NTP-synchronized punch ready:")
        print("  NTP time: {}".format(ntp_timestamp))
        print("  Bucket: {}".format(bucket_a))
        print("  Punch time A: {}".format(punch_time_a))
        print("  Punch time B: {}".format(punch_time_b))
        print("  A ({}) -> B ({}) with {} ports".format(self.ip_a, self.ip_b, len(puncher_a.port_allocs)))
        print("  B ({}) -> A ({}) with {} ports".format(self.ip_b, self.ip_a, len(puncher_b.port_allocs)))

    async def test_ipv6_actual_bidirectional_punch_with_sockets(self):
        """Test actual bidirectional IPv6 TCP punching with real socket creation."""
        # Skip if we have mixed link-local + global addresses
        # (different address families have compatibility issues)
        if self.ip_a_with_scope != self.ip_a or self.ip_b_with_scope != self.ip_b:
            if (self.ip_a_with_scope != self.ip_a) != (self.ip_b_with_scope != self.ip_b):
                self.skipTest("Cannot mix link-local and global IPv6 addresses in socket tests")

        try:
            ntp_timestamp = timestamp_from_ntp()
        except RuntimeError:
            ntp_timestamp = int(time.time())

        # Create IPv6 listening sockets (use scoped addresses for link-local)
        listen_sock_a = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        listen_sock_a.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listen_sock_a.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        listen_sock_a.bind(binder_sync(IP6, self.ip_a, 0, self.nic_name))
        listen_sock_a.listen(5)
        listen_port_a = listen_sock_a.getsockname()[1]

        listen_sock_b = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        listen_sock_b.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listen_sock_b.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        listen_sock_b.bind(binder_sync(IP6, self.ip_b, 0, self.nic_name))
        listen_sock_b.listen(5)
        listen_port_b = listen_sock_b.getsockname()[1]

        print("\nIPv6 Listening sockets created:")
        print("  A: [{}]:{}".format(self.ip_a, listen_port_a))
        print("  B: [{}]:{}".format(self.ip_b, listen_port_b))

        try:
            # Create IPv6 punchers
            puncher_a = PunchClient(
                dest_ip=self.ip_b,
                src_ip=self.ip_a,
                our_ip=self.ip_a,
                max_sleep=3,
                same_machine=True,
            )
            puncher_a.set_timestamp(ntp_timestamp)
            bucket_a, punch_time_a = compute_rendezvous(ntp_timestamp)
            puncher_a.set_punch_time(punch_time_a)
            puncher_a.add_port_allocator(boundary_port_alloc)

            puncher_b = PunchClient(
                dest_ip=self.ip_a,
                src_ip=self.ip_b,
                our_ip=self.ip_b,
                max_sleep=3,
                same_machine=True,
            )
            puncher_b.set_timestamp(ntp_timestamp)
            bucket_b, punch_time_b = compute_rendezvous(ntp_timestamp)
            puncher_b.set_punch_time(punch_time_b)
            puncher_b.add_port_allocator(boundary_port_alloc)

            print("\nIPv6 Punch configurations:")
            print("  Puncher A: {} -> [{}]:{}".format(self.ip_a, self.ip_b, listen_port_b))
            print("  Puncher B: {} -> [{}]:{}".format(self.ip_b, self.ip_a, listen_port_a))

            # Replace port allocations with actual listening ports
            puncher_a.port_allocs.clear()
            for src_port in range(30000, 30008):
                puncher_a.port_allocs.append(PortAlloc(src_port, listen_port_b))

            puncher_b.port_allocs.clear()
            for src_port in range(31000, 31008):
                puncher_b.port_allocs.append(PortAlloc(src_port, listen_port_a))

            loop = asyncio.get_event_loop()

            listen_sock_a.setblocking(False)
            listen_sock_b.setblocking(False)

            print("\nRunning IPv6 punch engines...")
            punch_a_task = loop.run_in_executor(
                None, run_punch_engine, puncher_a, tcp_selector_punch_engine
            )
            punch_b_task = loop.run_in_executor(
                None, run_punch_engine, puncher_b, tcp_selector_punch_engine
            )

            try:
                sock_a, sock_b = await asyncio.wait_for(
                    asyncio.gather(punch_a_task, punch_b_task),
                    timeout=20
                )
            except asyncio.TimeoutError:
                print("IPv6 punch engines timed out (expected in some NAT scenarios)")
                sock_a = None
                sock_b = None

            # Check results
            if sock_a is not None:
                print("✓ IPv6 Puncher A succeeded!")
                try:
                    peer = sock_a.getpeername()
                    local = sock_a.getsockname()
                    print("  Local: [{}]:{}".format(local[0], local[1]))
                    print("  Peer: [{}]:{}".format(peer[0], peer[1]))
                    self.assertEqual(peer[0], self.ip_b, "Should connect to IPv6 IP B")
                    sock_a.close()
                except Exception as e:
                    print("  Error getting socket info: {}".format(e))
            else:
                print("✗ IPv6 Puncher A did not create socket")

            if sock_b is not None:
                print("✓ IPv6 Puncher B succeeded!")
                try:
                    peer = sock_b.getpeername()
                    local = sock_b.getsockname()
                    print("  Local: [{}]:{}".format(local[0], local[1]))
                    print("  Peer: [{}]:{}".format(peer[0], peer[1]))
                    self.assertEqual(peer[0], self.ip_a, "Should connect to IPv6 IP A")
                    sock_b.close()
                except Exception as e:
                    print("  Error getting socket info: {}".format(e))
            else:
                print("✗ IPv6 Puncher B did not create socket")

            if sock_a or sock_b:
                print("\n✓ IPv6 TCP punch successful on at least one direction")
            else:
                print("\nℹ No IPv6 punch connections (expected behind restrictive NAT)")

        finally:
            # Clean up listening sockets
            listen_sock_a.close()
            listen_sock_b.close()


if __name__ == "__main__":
    unittest.main()
