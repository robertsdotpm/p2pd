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
  * Migration: when a legacy listen_ips-namespaced key file is
    present and the new path is empty, the legacy key is adopted
    (most-recently-modified wins) instead of forcing a fresh
    generation.
"""

import os
import shutil
import tempfile
import time
import unittest

from p2pd.node.node_utils import adopt_legacy_signing_key, load_signing_key


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

    def test_legacy_key_file_is_adopted(self):
        """When a stale listen_ips-keyed file is the only one on disk,
        load_signing_key should adopt it instead of minting a fresh key."""
        nics = [FakeNIC("ens34")]
        port = 12345

        # Plant a legacy key file with arbitrary contents.
        legacy_hex = "ab" * 32
        legacy_path = os.path.join(
            self.install_path,
            "PRIV_KEY_DONT_SHARE_legacy0123456789.hex",
        )
        with open(legacy_path, "w", encoding="utf-8") as fp:
            fp.write(legacy_hex)

        # Confirm adopt_legacy_signing_key picks it up.
        adopted = adopt_legacy_signing_key(self.install_path)
        self.assertEqual(adopted, legacy_hex)

        # Now load_signing_key should adopt + write to the new path
        # (a fresh load with different bytes would not equal legacy_hex).
        sk = load_signing_key(nics, ["10.0.1.76"], port, self.install_path)
        from binascii import hexlify
        self.assertEqual(hexlify(sk.to_string()).decode(), legacy_hex)

    def test_legacy_picks_most_recently_modified(self):
        """When several legacy files exist, the newest mtime wins."""
        older_path = os.path.join(
            self.install_path, "PRIV_KEY_DONT_SHARE_old.hex",
        )
        newer_path = os.path.join(
            self.install_path, "PRIV_KEY_DONT_SHARE_new.hex",
        )
        with open(older_path, "w", encoding="utf-8") as fp:
            fp.write("aa" * 32)
        # Set older mtime explicitly so the test isn't subject to fs
        # timestamp resolution flakes.
        old_time = time.time() - 3600
        os.utime(older_path, (old_time, old_time))

        with open(newer_path, "w", encoding="utf-8") as fp:
            fp.write("bb" * 32)

        adopted = adopt_legacy_signing_key(self.install_path)
        self.assertEqual(adopted, "bb" * 32)


if __name__ == "__main__":
    unittest.main()
