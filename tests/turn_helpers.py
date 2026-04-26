"""
Shared helpers for the test_turn_* split files.

The original test_turn.py was meant to host five AsyncTestCase classes
(loopback IPv4, multi-IP loopback IPv4, loopback IPv6, plugin IPv4,
plugin IPv6) but never had the bodies written.  Per CLAUDE.md
"Heavy tests live in their own file", each TURN test class now lives
in its own test_turn_*.py file so the runner gives it a fresh
subprocess and SSDP / TURN socket churn from prior classes can't
flake the loader.

This module is named turn_helpers.py (no test_ prefix) so the runner
doesn't pick it up as a test module.
"""

import asyncio

from aionetiface import IP4, IP6, SUB_ALL, to_b, to_s
from aionetiface.testing import FakeInterfaceFactory

from p2pd.traversal.plugins.turn.turn_client import TURNClient

from turn_server import (
    TURN_TEST_PASS,
    TURN_TEST_PORT,
    TURN_TEST_REALM,
    TURN_TEST_USER,
    TURNServer,
)


# How long to wait on TURN allocation / send / recv steps before treating
# the round-trip as broken.  Generous enough for cold loopback paths on
# the slowest VMs in the matrix without dragging the green path out.
TURN_OP_TIMEOUT = 12
TURN_RELAY_TIMEOUT = 8


def make_turn_client(af, dest, nic):
    """Return an uninitialised TURNClient targeted at the local test server."""
    return TURNClient(
        af=af,
        dest=dest,
        nic=nic,
        auth=(to_s(TURN_TEST_USER), to_s(TURN_TEST_PASS)),
        realm=to_s(TURN_TEST_REALM),
    )


async def start_turn_client(af, dest, nic, timeout=TURN_OP_TIMEOUT):
    """Construct + start() a TURNClient, returning it once allocation completes."""
    client = make_turn_client(af, dest, nic)
    await asyncio.wait_for(client.start(), timeout=timeout)
    await asyncio.wait_for(client.client_tup_future, timeout=timeout)
    await asyncio.wait_for(client.relay_tup_future, timeout=timeout)
    return client


async def whitelist_pair(client_a, client_b):
    """Have each client whitelist the other's source/relay tuple."""
    a_peer = await client_a.client_tup_future
    a_relay = await client_a.relay_tup_future
    b_peer = await client_b.client_tup_future
    b_relay = await client_b.relay_tup_future
    await client_a.accept_peer(b_peer, b_relay)
    await client_b.accept_peer(a_peer, a_relay)


async def relay_round_trip(sender, receiver, payload=b"hello-turn",
                           timeout=TURN_RELAY_TIMEOUT, attempts=4):
    """
    Send *payload* from *sender* through TURN and read it on *receiver*.

    UDP can drop the first packet if the permission install hasn't been
    fully processed by the server's relay socket; retry a handful of
    times before giving up.
    """
    payload = to_b(payload)
    for _ in range(attempts):
        await sender.send(payload)
        try:
            out = await asyncio.wait_for(
                receiver.recv(SUB_ALL, timeout=timeout),
                timeout=timeout + 1,
            )
        except asyncio.TimeoutError:
            out = None
        if out and payload in out:
            return out
    return None


async def close_clients(*clients):
    """Best-effort close of every client; never raises."""
    for c in clients:
        if c is None:
            continue
        try:
            await asyncio.wait_for(c.close(), timeout=5)
        except (asyncio.TimeoutError, OSError, ConnectionError):
            pass


async def close_server(server):
    """Best-effort close of the TURN server; never raises."""
    if server is None:
        return
    try:
        await asyncio.wait_for(server.close(), timeout=5)
    except (asyncio.TimeoutError, OSError, ConnectionError):
        pass


async def start_local_turn(test_self, nic, want_af):
    """
    Start a TURNServer on *nic* and skipTest if *want_af* didn't bind.

    Returns the started server.  The caller is responsible for closing
    it (use close_server in asyncTearDown).
    """
    server = TURNServer(nic)
    try:
        await server.start()
    except (OSError, ConnectionError):
        await close_server(server)
        test_self.skipTest("TURN server start failed (no usable loopback)")
    if want_af not in server.started_afs():
        await close_server(server)
        test_self.skipTest(
            "TURN server could not bind AF={0} (loopback unavailable)".format(want_af)
        )
    return server


async def fake_factory_or_skip(test_self):
    """Return a FakeInterfaceFactory or skipTest if it can't be built."""
    try:
        return await FakeInterfaceFactory.create()
    except (OSError, ConnectionError):
        test_self.skipTest("FakeInterfaceFactory could not enumerate routes")
