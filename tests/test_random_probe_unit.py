"""
Pure unit tests for the random-probe plugin.

No sockets, no event loop -- just the wire-format helpers, the
port-set generator, and the role-decision logic.  Designed to run
fast on every VM in the matrix so a flaky probe-side environment
can't hide a regression in the deterministic parts.
"""

import os
import struct
import unittest

from aionetiface.testing import AsyncTestCase

from aionetiface.nic.nat.nat_defs import (
    FULL_CONE,
    OPEN_INTERNET,
    RESTRICT_NAT,
    RESTRICT_PORT_NAT,
    SYMMETRIC_NAT,
)

from warpgate.traversal.plugins.random_probe.random_probe_defs import (
    DEFAULT_PROBE_COUNT,
    PROBE_LEN,
    PROBE_MAGIC,
    PROBE_PORT_HI,
    PROBE_PORT_LO,
    ROLE_CONE,
    ROLE_SYM,
)
from warpgate.traversal.plugins.random_probe.random_probe_lib import (
    decode_probe,
    encode_probe,
    random_probe_ports,
)
from warpgate.traversal.plugins.random_probe.main import is_symmetric_nat
from warpgate.traversal.plugins.random_probe.proto import RandomProbeMsg
# Plugin loader patches WIRE_NAME at install; unit tests bypass the
# loader so we set it here so pack() doesn't trip on the unset guard.
RandomProbeMsg.WIRE_NAME = "random_probe.RandomProbeMsg"


class TestProbeWireFormat(unittest.TestCase):
    """encode_probe / decode_probe round-trip and reject malformed inputs."""

    def test_encoded_length(self):
        nonce = os.urandom(16)
        buf = encode_probe(nonce, ROLE_CONE, 7)
        self.assertEqual(len(buf), PROBE_LEN)

    def test_magic_prefix(self):
        nonce = os.urandom(16)
        buf = encode_probe(nonce, ROLE_SYM, 0)
        self.assertEqual(buf[:4], PROBE_MAGIC)

    def test_round_trip_cone(self):
        nonce = os.urandom(16)
        buf = encode_probe(nonce, ROLE_CONE, 42)
        parsed = decode_probe(buf, nonce)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["role"], ROLE_CONE)
        self.assertEqual(parsed["idx"], 42)

    def test_round_trip_sym(self):
        nonce = os.urandom(16)
        buf = encode_probe(nonce, ROLE_SYM, 65535)
        parsed = decode_probe(buf, nonce)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["role"], ROLE_SYM)
        self.assertEqual(parsed["idx"], 65535)

    def test_decode_rejects_short(self):
        nonce = os.urandom(16)
        self.assertIsNone(decode_probe(b"too short", nonce))

    def test_decode_rejects_long(self):
        nonce = os.urandom(16)
        buf = encode_probe(nonce, ROLE_CONE, 0) + b"\x00"
        self.assertIsNone(decode_probe(buf, nonce))

    def test_decode_rejects_wrong_magic(self):
        nonce = os.urandom(16)
        buf = b"XXXX" + nonce + ROLE_CONE + struct.pack("!H", 0)
        self.assertIsNone(decode_probe(buf, nonce))

    def test_decode_rejects_wrong_nonce(self):
        nonce = os.urandom(16)
        other = os.urandom(16)
        buf = encode_probe(nonce, ROLE_CONE, 0)
        self.assertIsNone(decode_probe(buf, other))

    def test_decode_rejects_unknown_role(self):
        nonce = os.urandom(16)
        buf = PROBE_MAGIC + nonce + b"\x99" + struct.pack("!H", 0)
        self.assertIsNone(decode_probe(buf, nonce))

    def test_encode_rejects_bad_nonce_length(self):
        with self.assertRaises(ValueError):
            encode_probe(b"too short", ROLE_CONE, 0)

    def test_encode_rejects_unknown_role(self):
        with self.assertRaises(ValueError):
            encode_probe(b"\x00" * 16, b"\x05", 0)


class TestRandomProbePorts(unittest.TestCase):
    """random_probe_ports gives unique ports inside the documented range."""

    def test_returns_requested_count(self):
        ports = random_probe_ports(DEFAULT_PROBE_COUNT)
        self.assertEqual(len(ports), DEFAULT_PROBE_COUNT)

    def test_unique(self):
        ports = random_probe_ports(DEFAULT_PROBE_COUNT)
        self.assertEqual(len(set(ports)), len(ports))

    def test_within_range(self):
        ports = random_probe_ports(DEFAULT_PROBE_COUNT)
        for p in ports:
            self.assertGreaterEqual(p, PROBE_PORT_LO)
            self.assertLessEqual(p, PROBE_PORT_HI)

    def test_count_too_large_raises(self):
        with self.assertRaises(ValueError):
            random_probe_ports(PROBE_PORT_HI - PROBE_PORT_LO + 2)


class TestSymmetricNatPredicate(unittest.TestCase):
    """is_symmetric_nat is the single source of truth for role-decision.

    The plugin assigns "sym" role to symmetric NATs and "non_sym"
    to everything else (open internet, full cone, restricted,
    port-restricted, missing classifier).  We don't expose a
    positively-worded counterpart -- every potential name (cone /
    predictable / fixed-port) was misleading because the set is
    "everything except symmetric", not any one shape.
    """

    def test_symmetric_is_symmetric(self):
        self.assertTrue(is_symmetric_nat({"type": SYMMETRIC_NAT}))

    def test_full_cone_is_not_symmetric(self):
        self.assertFalse(is_symmetric_nat({"type": FULL_CONE}))

    def test_open_internet_is_not_symmetric(self):
        self.assertFalse(is_symmetric_nat({"type": OPEN_INTERNET}))

    def test_restrict_is_not_symmetric(self):
        self.assertFalse(is_symmetric_nat({"type": RESTRICT_NAT}))

    def test_restrict_port_is_not_symmetric(self):
        self.assertFalse(is_symmetric_nat({"type": RESTRICT_PORT_NAT}))

    def test_empty_dict_is_not_symmetric(self):
        # No NAT info -> assume non-symmetric.  Lets the algorithm
        # run on boxes where the classifier hasn't finished.
        self.assertFalse(is_symmetric_nat({}))

    def test_none_is_not_symmetric(self):
        self.assertFalse(is_symmetric_nat(None))


class TestRandomProbeMsg(unittest.TestCase):
    """RandomProbeMsg payload round-trips through to_dict / from_dict cleanly."""

    def test_payload_round_trip(self):
        m = RandomProbeMsg({
            "payload": {
                "role": "non_sym",
                "punch_time": 1700000000,
                "magic": "ab" * 16,
                "ext_ip": "203.0.113.5",
                "known_port": 50001,
                "probe_count": 256,
            },
        })
        d = m.payload.to_dict()
        self.assertEqual(d["role"], "non_sym")
        self.assertEqual(d["punch_time"], 1700000000)
        self.assertEqual(d["magic"], "ab" * 16)
        self.assertEqual(d["ext_ip"], "203.0.113.5")
        self.assertEqual(d["known_port"], 50001)
        self.assertEqual(d["probe_count"], 256)

    def test_pack_unpack(self):
        m = RandomProbeMsg({
            "payload": {
                "role": "sym",
                "punch_time": 1700000099,
                "magic": "cd" * 16,
                "ext_ip": "198.51.100.7",
                "known_port": 0,
                "probe_count": 320,
            },
        })
        buf = m.pack()
        # Wire = [name_len: 1][wire_name: ASCII][JSON].
        # Strip the framing prefix before re-parsing the JSON.
        name_len = buf[0]
        m2 = RandomProbeMsg.unpack(buf[1 + name_len:])
        self.assertEqual(m2.payload.role, "sym")
        self.assertEqual(m2.payload.known_port, 0)
        self.assertEqual(m2.payload.probe_count, 320)
        self.assertEqual(m2.payload.ext_ip, "198.51.100.7")


if __name__ == "__main__":
    unittest.main()
