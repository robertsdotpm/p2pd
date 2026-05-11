"""464XLAT / NAT64 prefix detection (RFC 7050).

Modern cellular carriers (T-Mobile USA, Reliance Jio, China Mobile,
many EU MNOs) deploy IPv6-only data planes with NAT64 at the carrier
edge.  An on-device CLAT then synthesises a v4 link locally so legacy
v4 sockets keep working transparently.  The carrier's NAT64 prefix is
discoverable per RFC 7050 by querying the well-known name
``ipv4only.arpa`` for AAAA: the returned address embeds the original
IPv4 in the carrier's NAT64 prefix.

Two consequences for p2pd:

  * A node whose only v4 path is via CLAT looks like dual-stack to
    aionetiface but its v4 candidates are NOT directly reachable from
    a peer with a real v4 path -- they're CLAT-translated.  If we
    detect CLAT, we can synthesise the equivalent v6 candidate
    (``<prefix>::<their_v4>``) and prefer the v6 path.

  * It catches one case the RFC 6598 (100.64/10) CGNAT detector
    misses: CLAT can hand the OS a 192.0.0.0/29 link which is NOT in
    100.64/10 but is no more reachable from outside.

This module exposes one helper, ``detect_nat64_prefix()``, that
returns the discovered NAT64 prefix as an ``IPRange`` (or ``None`` if
no NAT64 is operating).  Callers can then test peer.v4 against
``ipv6_addr_in_prefix(prefix + peer.v4)`` to choose the v6 candidate.

The lookup uses the system resolver, which on a CLAT-active host has
been hijacked to return synthesised AAAA for ipv4only.arpa.  No
external dependency required.

Reference: RFC 7050, https://www.rfc-editor.org/rfc/rfc7050
"""

import asyncio
import socket
from aionetiface import fstr, log


WELL_KNOWN_NAME = "ipv4only.arpa"

# The two well-known IPv4 addresses ipv4only.arpa points to.  Their
# synthesised AAAAs reveal the NAT64 prefix length and value.
WELL_KNOWN_V4 = ("192.0.0.170", "192.0.0.171")


async def detect_nat64_prefix(timeout=2.0):
    """Return the active NAT64 prefix as a string (e.g. "64:ff9b::") or None.

    Queries ipv4only.arpa for AAAA records via the system resolver.
    If the OS is on a CLAT-active link the resolver has been hijacked
    to synthesise an AAAA whose low-order bytes are 192.0.0.170 (the
    well-known IPv4).  Extract the prefix by stripping those low-order
    bytes from the AAAA record.

    Returns None if:
      - no AAAA records come back (no NAT64 active);
      - the AAAA records don't embed a recognised well-known v4 (the
        resolver isn't NAT64-aware);
      - the lookup times out or errors.
    """
    loop = asyncio.get_event_loop()

    def lookup():
        try:
            results = socket.getaddrinfo(
                WELL_KNOWN_NAME, None, socket.AF_INET6,
            )
            return [r[4][0] for r in results]
        except (socket.gaierror, OSError):
            return []

    try:
        aaaa_list = await asyncio.wait_for(
            loop.run_in_executor(None, lookup),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        log(fstr("nat64_detect: DNS lookup for {0} timed out",
                 (WELL_KNOWN_NAME,)))
        return None

    for aaaa in aaaa_list:
        prefix = extract_nat64_prefix(aaaa)
        if prefix is not None:
            log(fstr(
                "nat64_detect: NAT64 prefix {0} discovered via {1} -> {2}",
                (prefix, WELL_KNOWN_NAME, aaaa),
            ))
            return prefix

    log("nat64_detect: no NAT64 prefix synthesised; assuming native v4")
    return None


def extract_nat64_prefix(aaaa):
    """Given a synthesised IPv6 address, return its NAT64 prefix.

    Per RFC 6052 the well-known v4 (192.0.0.170 = 0xc000:00aa) appears
    in the low-order 32 bits of an RFC 7050 synthesised AAAA, so the
    prefix is the upper 96 bits.  Returns the prefix as a string in
    standard /96 form (e.g. "64:ff9b::") or None if no well-known v4
    is embedded.
    """
    try:
        packed = socket.inet_pton(socket.AF_INET6, aaaa)
    except (OSError, ValueError):
        return None
    if len(packed) != 16:
        return None
    # The low 4 bytes should be one of the well-known v4 addresses.
    low4 = socket.inet_ntop(socket.AF_INET, packed[12:])
    if low4 not in WELL_KNOWN_V4:
        return None
    # Zero the low 32 bits, render the result as the canonical v6 prefix.
    prefix_bytes = packed[:12] + b"\x00\x00\x00\x00"
    return socket.inet_ntop(socket.AF_INET6, prefix_bytes)


def synthesise_nat64_addr(prefix, peer_v4):
    """Embed peer_v4 into prefix (string form) and return the synthesised v6 addr."""
    try:
        prefix_packed = socket.inet_pton(socket.AF_INET6, prefix)
        v4_packed = socket.inet_pton(socket.AF_INET, peer_v4)
    except (OSError, ValueError):
        return None
    if len(prefix_packed) != 16 or len(v4_packed) != 4:
        return None
    # Replace low 32 bits of prefix with v4.
    synth = prefix_packed[:12] + v4_packed
    return socket.inet_ntop(socket.AF_INET6, synth)
