"""
Index for the test_turn_* split.

The TURN tests are network-heavy and were originally laid out as one
big file with five AsyncTestCase classes that never actually had
their bodies written.  Per CLAUDE.md "Heavy tests live in their own
file" each class now lives in its own test_turn_*.py so the runner
gives it a fresh subprocess.

Layout:

  test_turn_loopback.py         IPv4 loopback round-trip (one bind IP)
  test_turn_loopback_alt.py     IPv4 loopback round-trip across two
                                127.0.0.x aliases (skips on macOS, where
                                only 127.0.0.1 is bindable by default)
  test_turn_loopback_ipv6.py    IPv6 loopback round-trip on ::1
  test_auto_connect_turn.py     End-to-end TURN fallback through
                                auto_connect, using the local TURN
                                server with patched get_infra

Shared helpers live in turn_helpers.py (no test_ prefix so the
runner doesn't pick it up as a test module) and in turn_server.py.

The runner discovers test_*.py files; this file intentionally has no
test classes so it stays cheap to import.
"""
