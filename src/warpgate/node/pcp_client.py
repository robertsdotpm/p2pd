"""Port Control Protocol client (RFC 6887).

PCP is the modern alternative to UPnP IGD for asking a NAT / firewall
to install an inbound mapping.  Where UPnP is SOAP over HTTP and is
restricted to UPnP-IGD CPEs (mostly home routers), PCP is a tiny UDP
protocol that the same CPEs increasingly support AND that several
carrier CGN deployments expose for explicit-port requests.  It also
covers IPv6 firewall pinhole creation in a way that consumer IGDv2
implementations frequently get wrong.

Discovery: per RFC 7723 a host can address PCP requests to the
well-known anycast addresses 192.0.0.9 (IPv4) and 2001:1::1 (IPv6).
Carriers that operate PCP commonly route those anycast prefixes to
their CGN gateway.  As a fallback we also send to the host's default
gateway (which is what most home routers honour even without
anycast).

Wire format references:
  RFC 6887 7 (common header), 11 (MAP opcode), 8 (result codes)
  RFC 7723 (anycast addresses)

This module exposes one async helper, ``pcp_request_mapping``, that
sends a single MAP request and returns the parsed response (or None
on no-response / failure).  It does NOT renew or maintain mappings;
the caller is responsible for refreshing before the granted lifetime
expires (typically 7200 s, half the default 86400 s requested).
"""

import asyncio
import os
import socket
import struct
from aionetiface import fstr, log


PCP_VERSION = 2
PCP_PORT = 5351
PCP_ANYCAST_V4 = "192.0.0.9"
PCP_ANYCAST_V6 = "2001:1::1"

OPCODE_MAP = 1
RESPONSE_BIT = 0x80

DEFAULT_LIFETIME = 7200  # 2 hours; matches PCP spec recommendation.

PROTOCOL_TCP = 6
PROTOCOL_UDP = 17

RESULT_CODES = {
    0: "SUCCESS",
    1: "UNSUPP_VERSION",
    2: "NOT_AUTHORIZED",
    3: "MALFORMED_REQUEST",
    4: "UNSUPP_OPCODE",
    5: "UNSUPP_OPTION",
    6: "MALFORMED_OPTION",
    7: "NETWORK_FAILURE",
    8: "NO_RESOURCES",
    9: "UNSUPP_PROTOCOL",
    10: "USER_EX_QUOTA",
    11: "CANNOT_PROVIDE_EXTERNAL",
    12: "ADDRESS_MISMATCH",
    13: "EXCESSIVE_REMOTE_PEERS",
}


def pack_client_ip(client_ip):
    """Return the 16-byte client-IP field for the PCP request header.

    PCP carries the client IP as a 128-bit value: native IPv6 if v6,
    IPv4-mapped (::ffff:a.b.c.d) if v4.  RFC 6887 7.1.
    """
    if ":" in client_ip:
        return socket.inet_pton(socket.AF_INET6, client_ip)
    v4 = socket.inet_pton(socket.AF_INET, client_ip)
    return b"\x00" * 10 + b"\xff\xff" + v4


def build_map_request(
    client_ip, internal_port, suggested_ext_port,
    proto=PROTOCOL_TCP, lifetime=DEFAULT_LIFETIME, nonce=None,
):
    """Build a 60-byte PCP MAP request as bytes.

    Header (24 bytes) + MAP opcode data (36 bytes).  See RFC 6887 7 / 11.
    """
    if nonce is None:
        nonce = os.urandom(12)
    elif len(nonce) != 12:
        raise ValueError("PCP mapping nonce must be exactly 12 bytes")

    header = struct.pack(
        "!BB H I",
        PCP_VERSION,
        OPCODE_MAP,  # R bit clear, opcode 1
        0,           # reserved (16 bits)
        lifetime,
    )
    header += pack_client_ip(client_ip)

    # All-zero suggested external IP = "any".  CPE picks one.
    suggested_ext_ip = b"\x00" * 16
    map_payload = (
        nonce
        + struct.pack("!B 3x", proto)
        + struct.pack("!HH", internal_port, suggested_ext_port)
        + suggested_ext_ip
    )
    return header + map_payload, nonce


def parse_map_response(buf):
    """Parse a 60-byte PCP MAP response; return a dict or None on malformed."""
    if len(buf) < 60:
        return None
    version, r_opcode, reserved, result_code = struct.unpack("!BBBB", buf[:4])
    if version != PCP_VERSION:
        return None
    if not (r_opcode & RESPONSE_BIT):
        return None
    if (r_opcode & ~RESPONSE_BIT) != OPCODE_MAP:
        return None
    lifetime, epoch_time = struct.unpack("!II", buf[4:12])
    # buf[12:24] is 12 reserved bytes.
    nonce = buf[24:36]
    proto = buf[36]
    internal_port, ext_port = struct.unpack("!HH", buf[40:44])
    ext_ip_bytes = buf[44:60]
    # If the external IP looks like an IPv4-mapped v6, render as v4.
    if ext_ip_bytes[:10] == b"\x00" * 10 and ext_ip_bytes[10:12] == b"\xff\xff":
        ext_ip = socket.inet_ntop(socket.AF_INET, ext_ip_bytes[12:])
    else:
        ext_ip = socket.inet_ntop(socket.AF_INET6, ext_ip_bytes)

    return {
        "result_code": result_code,
        "result_name": RESULT_CODES.get(result_code, "UNKNOWN({0})".format(result_code)),
        "lifetime": lifetime,
        "epoch_time": epoch_time,
        "nonce": nonce,
        "proto": proto,
        "internal_port": internal_port,
        "external_port": ext_port,
        "external_ip": ext_ip,
    }


async def pcp_request_mapping(
    client_ip, gateway_ip, internal_port,
    proto=PROTOCOL_TCP, suggested_ext_port=0,
    lifetime=DEFAULT_LIFETIME, timeout=2.0,
):
    """Send a PCP MAP request to gateway_ip and await one response.

    Returns the parsed response dict on success or None on timeout /
    malformed reply.  ``proto`` is the IANA protocol number (6 = TCP,
    17 = UDP).  ``suggested_ext_port`` of 0 lets the CPE pick.

    Per RFC 6887 8.1 the request should be retransmitted with
    exponential backoff if no reply arrives; we keep this single-shot
    for now since the caller already races multiple gateways in
    parallel.
    """
    is_v6 = ":" in gateway_ip
    af = socket.AF_INET6 if is_v6 else socket.AF_INET
    request, nonce = build_map_request(
        client_ip, internal_port, suggested_ext_port,
        proto=proto, lifetime=lifetime,
    )

    sock = socket.socket(af, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        try:
            await asyncio.get_event_loop().sock_sendto(
                sock, request, (gateway_ip, PCP_PORT),
            ) if False else None  # sock_sendto exists 3.11+; use sendto.
        except Exception:
            pass
        # Stick with plain sendto for portability across 3.5-3.12.
        sock.sendto(request, (gateway_ip, PCP_PORT))

        loop = asyncio.get_event_loop()
        fut = loop.create_future()

        def on_readable():
            try:
                data, _ = sock.recvfrom(4096)
            except (BlockingIOError, OSError) as exc:
                if not fut.done():
                    fut.set_exception(exc)
                return
            if not fut.done():
                fut.set_result(data)

        loop.add_reader(sock.fileno(), on_readable)
        try:
            data = await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            log(fstr(
                "pcp: no response from {0}:{1} within {2}s (gateway may "
                "not run PCP, or it is filtered)",
                (gateway_ip, PCP_PORT, timeout),
            ))
            return None
        finally:
            try:
                loop.remove_reader(sock.fileno())
            except (OSError, ValueError):
                pass
    finally:
        sock.close()

    parsed = parse_map_response(data)
    if parsed is None:
        log("pcp: malformed response from {0}".format(gateway_ip))
        return None
    if parsed["nonce"] != nonce:
        log("pcp: nonce mismatch in response from {0} (possible reply replay)".format(gateway_ip))
        return None
    if parsed["result_code"] != 0:
        log(fstr(
            "pcp: gateway {0} rejected MAP: {1} (lifetime={2})",
            (gateway_ip, parsed["result_name"], parsed["lifetime"]),
        ))
        return parsed
    log(fstr(
        "pcp: gateway {0} granted mapping ext={1}:{2} -> internal={3} "
        "lifetime={4}s",
        (
            gateway_ip, parsed["external_ip"], parsed["external_port"],
            parsed["internal_port"], parsed["lifetime"],
        ),
    ))
    return parsed


async def pcp_try_anycast_and_gateway(
    af, client_ip, gateway_ip, internal_port,
    proto=PROTOCOL_TCP, suggested_ext_port=0,
):
    """Race PCP request at the RFC 7723 anycast address and gateway_ip.

    Returns the first successful parsed response (result_code == 0) or
    None.  Anycast covers carriers that explicitly route 192.0.0.9 /
    2001:1::1 to their CGN PCP server (RFC 7723); the gateway request
    covers home routers that have PCP enabled on the LAN interface.
    """
    anycast = PCP_ANYCAST_V6 if af == socket.AF_INET6 else PCP_ANYCAST_V4
    targets = [anycast]
    if gateway_ip and gateway_ip != anycast:
        targets.append(gateway_ip)

    tasks = [
        asyncio.ensure_future(
            pcp_request_mapping(
                client_ip, t, internal_port,
                proto=proto, suggested_ext_port=suggested_ext_port,
            )
        )
        for t in targets
    ]
    winner = None
    try:
        for fut in asyncio.as_completed(tasks):
            parsed = await fut
            if parsed and parsed.get("result_code") == 0:
                winner = parsed
                break
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    return winner
