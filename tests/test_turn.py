"""
Tests for the TURN client, relay server, and traversal plugin.

Two complementary test suites:

  TestTURNLoopback     --  Two TURNClient instances on 127.0.0.1 (same loopback
                           IP, different source ports) relay a message through
                           the local TURNServer.  Always runs.

  TestTURNNicIPs       --  Same flow but each client is bound to a different NIC
                           IP (e.g. 10.0.1.76 / 10.0.1.100).  Skipped when the
                           machine has fewer than two private IPs on the same
                           interface.

  TestTURNLoopbackIPv6 --  Mirrors TestTURNLoopback over IPv6 (::1).
                           Skipped when IPv6 is not available.

  TestTURNPluginIPv6   --  Exercises TURNPlugin end-to-end over IPv6.
                           Skipped when IPv6 is not available.

  TestTURNPlugin       --  Exercises the TURNPlugin traversal plugin end-to-end
                           with a simulated signalling channel and the local
                           TURNServer patched into TURN_SERVERS.
"""

import asyncio
import copy
import sys
import unittest
from unittest.mock import patch



import aionetiface
from aionetiface import (
    Interface,
    Pipe,
    UDP,
    IP4,
    IP6,
    EXT_BIND,
    to_s,
    rand_plain,
    async_wrap_errors,
    log_exception,
    bind_closure,
    binder_async,
    ErrorNoReply,
)

from p2pd.traversal.plugins.turn.turn_client import TURNClient
from p2pd.traversal.plugins.turn.main import TURNPlugin
from p2pd.traversal.plugins.turn.turn_utils import get_turn_client
from p2pd.protocol.proto_msg import TURNMsg

from turn_server import (
    TURNServer,
    TURN_TEST_PORT,
    TURN_TEST_REALM,
    TURN_TEST_USER,
    TURN_TEST_PASS,
    make_local_turn_server_entry,
)
from aionetiface.testing import make_fake_nic


# ──────────────────────────────────────────────────────────────────────────────
from aionetiface.testing import AsyncTestCase


# ──────────────────────────────────────────────────────────────────────────────
# Shared fixture helpers
# ──────────────────────────────────────────────────────────────────────────────


def make_turn_client(nic, dest_ip="127.0.0.1", port=TURN_TEST_PORT):
    """Return an uninitialised TURNClient aimed at the local test server."""
    return TURNClient(
        af=IP4,
        dest=(dest_ip, port),
        nic=nic,
        auth=(to_s(TURN_TEST_USER), to_s(TURN_TEST_PASS)),
        realm=to_s(TURN_TEST_REALM),
    )


async def start_client(nic, dest_ip="127.0.0.1", port=TURN_TEST_PORT, timeout=12):
    """Create and start a TURNClient, returning it once allocation is done."""
    client = make_turn_client(nic, dest_ip, port)
    await asyncio.wait_for(client.start(), timeout)
    return client


def make_turn_client_ip6(nic, dest_ip="::1", port=TURN_TEST_PORT):
    """Return an uninitialised IPv6 TURNClient aimed at the local test server."""
    return TURNClient(
        af=IP6,
        dest=(dest_ip, port),
        nic=nic,
        auth=(to_s(TURN_TEST_USER), to_s(TURN_TEST_PASS)),
        realm=to_s(TURN_TEST_REALM),
    )


async def start_client_ip6(nic, dest_ip="::1", port=TURN_TEST_PORT, timeout=12):
    """Create and start an IPv6 TURNClient, returning it once allocation is done."""
    client = make_turn_client_ip6(nic, dest_ip, port)
    await asyncio.wait_for(client.start(), timeout)
    return client


# ──────────────────────────────────────────────────────────────────────────────
# Test 1 -- Loopback relay (same 127.0.0.1, different ports)
# ──────────────────────────────────────────────────────────────────────────────


