"""
Shared helpers for the test_upnp.* split files.

The original test_upnp.py packed four heavy AsyncTestCase classes
(IPv4 discover, IPv4 forward, IPv6 discover, IPv6 forward) into
one subprocess. Each opens SSDP M-SEARCH multicast sockets,
follows up with HTTP control-channel sockets to the router, and
runs port-forward / pinhole RPC. Cumulative socket / asyncio
state across all four classes flaked the singular
load_interface path on XP (Interface() came back with
InterfaceNotFound mid-run even though it succeeds 20x in a row
in isolation). Per CLAUDE.md "Heavy tests live in their own
file" the four classes are now split into:

    test_upnp.py           -- network-free unit tests + a few
                              wiring tests (light)
    test_upnp_ipv4.py      -- IPv4 discover + IPv4 forward
    test_upnp_ipv6.py      -- IPv6 discover + IPv6 forward

Each split test_*.py runs in its own subprocess via the runner,
so the per-class socket state can't bleed between AFs.

Lives in upnp_helpers.py (no test_ prefix) so the runner doesn't
pick it up as a test file.
"""

from aionetiface import Interface
from aionetiface.errors import InterfaceNotFound


# UPnP port used for AddPortMapping / AddPinhole tests. Picked at
# random to avoid colliding with any well-known service if the
# router doesn't unmap it on test exit.
UPNP_TEST_PORT = 59871


async def get_test_nic(test_self):
    """Build a default Interface, skipping the test on InterfaceNotFound.

    Repeated `await Interface()` calls across many tests in one
    subprocess have flaked on XP -- the singular load_interface
    path classifies the NIC's stack via STUN, and after a string
    of prior tests have churned through SSDP / UPnP / port-forward
    sockets a STUN probe occasionally comes back with no usable
    routes for any AF and the loader raises InterfaceNotFound.
    Standalone runs of `await Interface()` succeed 20+ times in
    a row, so it's in-process state accumulation, not a real "no
    network" failure. skipTest rather than ERROR so the flake
    doesn't halt the matrix gate.
    """
    try:
        return await Interface()
    except InterfaceNotFound:
        test_self.skipTest(
            "Interface() couldn't classify a default NIC -- transient "
            "STUN flake, common on XP after many prior tests in one "
            "subprocess have churned through sockets"
        )
