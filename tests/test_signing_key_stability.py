"""
load_signing_key must NOT churn identity when listen_ips changes.

Regression for the IPv6 churn bug: kernel-assigned privacy /
temporary addresses rotate every few hours; the old key derivation
mixed them into the on-disk path so every rotation generated a fresh
key + pubkey + node_id + nickname registration.

The fix keys the path by (sorted NIC names, listen_port) only.  These
tests pin that behaviour:

  * Same (NICs, port), different listen_ips -> same key returned.
  * Different listen_port -> different on-disk file, fresh key.
  * Different NIC set -> different on-disk file, fresh key.
"""

import os
import shutil
import tempfile
import time
import unittest

from p2pd.node.node_utils import load_signing_key


class FakeNIC:
    """Minimal NIC stub for hashing -- only `name` is read."""

    def __init__(self, name):
        self.name = name


class TestSigningKeyStability(unittest.TestCase):
    """Identity must persist across listen_ips churn."""

    def setUp(self):
        self.install_path = tempfile.mkdtemp(prefix="p2pd-sk-test-")

    def tearDown(self):
        shutil.rmtree(self.install_path, ignore_errors=True)

    def test_listen_ips_change_does_not_rotate_key(self):
        """Two startups with different listen_ips share the same on-disk key."""
        nics = [FakeNIC("ens34"), FakeNIC("ens37")]
        port = 12345

        sk_a = load_signing_key(
            nics,
            ["10.0.1.76", "fe80::1"],
            port,
            self.install_path,
        )
        sk_b = load_signing_key(
            nics,
            # Same NICs + port, but a fresh batch of IPv6 temp
            # addresses -- this used to mint a new SK.
            ["10.0.1.76", "fe80::2", "2001:db8::dead:beef"],
            port,
            self.install_path,
        )

        self.assertEqual(
            sk_a.to_string(), sk_b.to_string(),
            "load_signing_key returned different SKs for the same "
            "(NIC, port) -- listen_ips churn is leaking into the hash",
        )

        # Exactly one key file should exist on disk.
        keys = [n for n in os.listdir(self.install_path)
                if n.startswith("PRIV_KEY_DONT_SHARE_")]
        self.assertEqual(len(keys), 1, "expected exactly one key file: {0}".format(keys))

    def test_different_port_yields_different_key(self):
        """Two distinct (NIC, port) configs still get distinct keys."""
        nics = [FakeNIC("ens34")]

        sk_a = load_signing_key(nics, ["10.0.1.76"], 12345, self.install_path)
        sk_b = load_signing_key(nics, ["10.0.1.76"], 12346, self.install_path)

        self.assertNotEqual(
            sk_a.to_string(), sk_b.to_string(),
            "different listen_port should still produce a different key",
        )

    def test_different_nic_sets_yield_different_keys(self):
        """Two nodes loading distinct NIC sets from the same install_path
        must NOT collide on the same key -- regression for the migration
        bug where legacy file adoption put two distinct configs onto the
        same key."""
        nics_a = [FakeNIC("ens34")]
        nics_b = [FakeNIC("ens37")]
        port = 12345

        sk_a = load_signing_key(nics_a, ["10.0.1.76"], port, self.install_path)
        sk_b = load_signing_key(nics_b, ["10.0.1.76"], port, self.install_path)

        self.assertNotEqual(
            sk_a.to_string(), sk_b.to_string(),
            "two nodes on different NICs must have distinct keys -- "
            "the migration regression let them collide on a shared "
            "legacy file",
        )

    def test_legacy_files_left_alone(self):
        """Legacy listen_ips-namespaced files MUST NOT be auto-adopted
        across distinct (NIC, port) loads -- doing so cross-pollutes
        identities. The fix generates a fresh key per new-scheme path
        and leaves legacy files untouched on disk for the user to
        clean up manually."""
        nics = [FakeNIC("ens34")]
        port = 12345

        # Plant a legacy file with arbitrary contents.
        legacy_hex = "ab" * 32
        legacy_path = os.path.join(
            self.install_path,
            "PRIV_KEY_DONT_SHARE_legacy0123456789.hex",
        )
        with open(legacy_path, "w", encoding="utf-8") as fp:
            fp.write(legacy_hex)

        sk = load_signing_key(nics, ["10.0.1.76"], port, self.install_path)
        from binascii import hexlify
        sk_hex = hexlify(sk.to_string()).decode()

        # The new-scheme key must NOT match the legacy file -- a
        # fresh key was generated.
        self.assertNotEqual(
            sk_hex, legacy_hex,
            "load_signing_key auto-adopted a legacy file -- this "
            "causes pubkey collisions when two distinct (NIC, port) "
            "configs share an install_path",
        )

        # Legacy file remains intact -- we don't delete crypto material.
        with open(legacy_path, "r", encoding="utf-8") as fp:
            self.assertEqual(fp.read(), legacy_hex)


if __name__ == "__main__":
    unittest.main()
