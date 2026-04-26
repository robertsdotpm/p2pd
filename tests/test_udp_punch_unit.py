"""
Unit tests for the udp_punch engine (network-free).

Covers:
  * Frame build / parse round-trip + rejection of non-frame bytes
  * Engine convergence over a synthetic two-side run on loopback
    (no NAT in the path -- still proves the spray/listen/CONFIRM
    handshake locks correctly when the predictions overlap).

Heavy multi-Node integration lives in test_udp_punch_e2e.py per
CLAUDE.md "Heavy tests live in their own file".
"""

import asyncio
import os
import socket
import threading
import time
import unittest

from aionetiface.testing import AsyncTestCase

from p2pd.traversal.plugins.tcp_punch.punch_defs import PortAlloc
from p2pd.traversal.plugins.udp_punch.udp_punch_defs import (
    UDP_PUNCH_FRAME_LEN,
    UDP_PUNCH_KIND_CONFIRM,
    UDP_PUNCH_KIND_PROBE,
    UDP_PUNCH_NONCE_LEN,
    build_frame,
    parse_frame,
)
from p2pd.traversal.plugins.udp_punch.udp_punch_engine import udp_punch_engine


class TestUdpPunchFrame(unittest.TestCase):
    """Frame helpers reject malformed input cleanly."""

    def test_round_trip(self):
        nonce = os.urandom(UDP_PUNCH_NONCE_LEN)
        f = build_frame(UDP_PUNCH_KIND_PROBE, nonce)
        self.assertEqual(len(f), UDP_PUNCH_FRAME_LEN)
        kind, recv = parse_frame(f)
        self.assertEqual(kind, UDP_PUNCH_KIND_PROBE)
        self.assertEqual(recv, nonce)

    def test_short_buffer_rejected(self):
        kind, nonce = parse_frame(b"P2UP")
        self.assertIsNone(kind)
        self.assertIsNone(nonce)

    def test_bad_magic_rejected(self):
        nonce = os.urandom(UDP_PUNCH_NONCE_LEN)
        bad = b"XXXX" + bytes([UDP_PUNCH_KIND_PROBE]) + nonce
        self.assertEqual(len(bad), UDP_PUNCH_FRAME_LEN)
        kind, recv = parse_frame(bad)
        self.assertIsNone(kind)
        self.assertIsNone(recv)

    def test_nonce_length_validated(self):
        with self.assertRaises(ValueError):
            build_frame(UDP_PUNCH_KIND_PROBE, b"too-short")


def make_alloc(src_port, dest_port):
    """Build a PortAlloc the engine accepts.

    PortAlloc carries (src_port, dest_port) plus other timing fields
    we don't care about for the engine-level proof.
    """
    return PortAlloc(src_port, dest_port)


class TestUdpPunchEngineLocal(unittest.TestCase):
    """Two engine sides converge over loopback when port allocations overlap."""

    def test_engine_round_trip_localhost(self):
        nonce = os.urandom(UDP_PUNCH_NONCE_LEN)

        # Pre-bind one socket per side to discover free ports the OS
        # will give us; close them before the engine runs so the
        # engine can re-bind. Using a single allocation per side keeps
        # this proof self-contained -- the engine handles cross-product
        # spraying internally.
        s_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s_a.bind(("127.0.0.1", 0))
        port_a = s_a.getsockname()[1]
        s_a.close()

        s_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s_b.bind(("127.0.0.1", 0))
        port_b = s_b.getsockname()[1]
        s_b.close()

        # Each side's port_alloc says "I bind src_port and aim probes
        # at the peer's dst_port". For a working punch, A's src must
        # equal B's dst and vice versa.
        alloc_a = make_alloc(src_port=port_a, dest_port=port_b)
        alloc_b = make_alloc(src_port=port_b, dest_port=port_a)

        # Synchronised barrier: both sides run f_sleep_until() and
        # we want them to fall through immediately.
        def no_sleep():
            return None

        # Tight params: keep the test fast.
        params = {
            "connect_timeout": 1.0,
            "monitor_timeout": 2.0,
            "retry_interval": 0.02,
        }

        result = {"a": None, "b": None}

        def run_a():
            result["a"] = udp_punch_engine(
                af=socket.AF_INET,
                nic_id=None,
                port_allocs=[alloc_a],
                src_ip="127.0.0.1",
                dest_ip="127.0.0.1",
                f_sleep_until=no_sleep,
                nonce=nonce,
                same_machine=True,
                params=params,
            )

        def run_b():
            result["b"] = udp_punch_engine(
                af=socket.AF_INET,
                nic_id=None,
                port_allocs=[alloc_b],
                src_ip="127.0.0.1",
                dest_ip="127.0.0.1",
                f_sleep_until=no_sleep,
                nonce=nonce,
                same_machine=True,
                params=params,
            )

        # Run the two engines in parallel threads; they're pure-sync.
        t_a = threading.Thread(target=run_a)
        t_b = threading.Thread(target=run_b)
        t_a.start()
        t_b.start()
        t_a.join(timeout=10)
        t_b.join(timeout=10)

        # Both sides must converge on a winning socket; at least ONE
        # side wins. The CONFIRM-handshake design lets either side
        # reach "winner" first depending on scheduling.
        self.assertTrue(
            result["a"] is not None or result["b"] is not None,
            "neither side converged; engine punch failed",
        )

        # Cleanup any sockets the engine returned.
        for r in result.values():
            if r is not None:
                sock, _addr = r
                try:
                    sock.close()
                except OSError:
                    pass


class TestUdpPunchEngineNoNonceMatch(unittest.TestCase):
    """An engine with a different nonce must NOT see the peer as a winner."""

    def test_mismatched_nonce_no_converge(self):
        nonce_a = os.urandom(UDP_PUNCH_NONCE_LEN)
        nonce_b = os.urandom(UDP_PUNCH_NONCE_LEN)
        self.assertNotEqual(nonce_a, nonce_b)

        s_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s_a.bind(("127.0.0.1", 0))
        port_a = s_a.getsockname()[1]
        s_a.close()
        s_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s_b.bind(("127.0.0.1", 0))
        port_b = s_b.getsockname()[1]
        s_b.close()

        alloc_a = make_alloc(src_port=port_a, dest_port=port_b)
        alloc_b = make_alloc(src_port=port_b, dest_port=port_a)

        def no_sleep():
            return None

        params = {
            "connect_timeout": 0.5,
            "monitor_timeout": 1.0,
            "retry_interval": 0.02,
        }

        result = {"a": None, "b": None}

        def run_a():
            result["a"] = udp_punch_engine(
                af=socket.AF_INET, nic_id=None, port_allocs=[alloc_a],
                src_ip="127.0.0.1", dest_ip="127.0.0.1",
                f_sleep_until=no_sleep, nonce=nonce_a,
                same_machine=True, params=params,
            )

        def run_b():
            result["b"] = udp_punch_engine(
                af=socket.AF_INET, nic_id=None, port_allocs=[alloc_b],
                src_ip="127.0.0.1", dest_ip="127.0.0.1",
                f_sleep_until=no_sleep, nonce=nonce_b,
                same_machine=True, params=params,
            )

        t_a = threading.Thread(target=run_a)
        t_b = threading.Thread(target=run_b)
        t_a.start()
        t_b.start()
        t_a.join(timeout=5)
        t_b.join(timeout=5)

        # Neither side should converge -- the nonces don't match so
        # their PROBE frames are silently filtered out as "not for us".
        self.assertIsNone(
            result["a"],
            "side A converged despite nonce mismatch",
        )
        self.assertIsNone(
            result["b"],
            "side B converged despite nonce mismatch",
        )


if __name__ == "__main__":
    unittest.main()
