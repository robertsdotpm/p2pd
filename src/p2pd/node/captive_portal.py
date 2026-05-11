"""Captive portal detection via canary HTTP requests.

Hotel / conference / coffee-shop / airport / hospital networks
frequently sit behind a captive portal that intercepts unauthenticated
HTTP, redirects to a sign-in page, and either silently drops or rate-
limits all other traffic until the user clicks through.  From inside
the portal, p2pd's MQTT signal channel, STUN probes, TURN allocations,
and any direct-connect attempt all look like "the network is down"
because the portal NATs HTTPS but blocks 1883 / 3478 / random UDP.

The canonical detection trick is to GET a known endpoint that returns
a fixed signature on the open internet.  If we get the expected
signature, no portal.  If we get a redirect, an HTML login page, or
random content, we're behind a portal.  The endpoints used here are
the public probes baked into every major OS:

  - Android: ``http://connectivitycheck.gstatic.com/generate_204``
    returns 204 No Content with no body on open internet.
  - Apple: ``http://captive.apple.com/hotspot-detect.html`` returns
    a short HTML body containing the literal string "Success".
  - Microsoft: ``http://www.msftconnecttest.com/connecttest.txt``
    returns "Microsoft Connect Test".

We probe at least two of those concurrently and trust an open verdict
only when ALL probes return their expected signature.  Any probe that
fails to match counts as a portal.  This is conservative -- a single
flaky DNS answer can produce a false-portal verdict -- but the cost
of a false positive (we log a warning + still try to connect) is
much lower than a false negative (we silently NO_ECHO behind a portal
the user could have clicked through).

The check is opt-in: callers ask for it explicitly at gate startup or
before a connect attempt.  Returns a small dict so a future UI layer
can surface the portal URL to the user.

RFC 8908 / RFC 8910 add a structured way for routers to advertise a
captive portal API via DHCP / Router Advertisement.  Modern OS stacks
already consume those; in 2026 most portals still rely on the
heuristic above as a fallback.

Reference: RFC 8908, RFC 8910, Apple developer note on captive
portal compatibility, Tailscale KB 1457 "Using Tailscale with
captive portals".
"""

import asyncio
import socket
from aionetiface import fstr, log


# Each entry: (host, path, expected_status, expected_body_substr)
# expected_body_substr=None means "no body check, status alone is enough".
PROBES = [
    ("connectivitycheck.gstatic.com", "/generate_204", 204, None),
    ("captive.apple.com", "/hotspot-detect.html", 200, b"Success"),
    ("www.msftconnecttest.com", "/connecttest.txt", 200, b"Microsoft Connect Test"),
]


PROBE_TIMEOUT_S = 4.0


async def probe_one(host, path, expected_status, expected_body):
    """GET host:80/path; return True iff the response matches expectations.

    Plain HTTP (port 80) is intentional: captive portals intercept HTTP
    but pass HTTPS, so HTTPS probes can't see the portal.  All three
    canonical endpoints serve their canary over plain HTTP for this
    exact reason.
    """
    loop = asyncio.get_event_loop()
    try:
        infos = await loop.getaddrinfo(host, 80, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        log(fstr("captive_portal: DNS lookup failed for {0}", (host,)))
        return False
    if not infos:
        return False
    family, sock_type, proto, _, sockaddr = infos[0]

    request = (
        "GET " + path + " HTTP/1.0\r\n"
        "Host: " + host + "\r\n"
        "User-Agent: p2pd-captive-probe/1\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")

    sock = socket.socket(family, sock_type, proto)
    sock.setblocking(False)
    try:
        try:
            await asyncio.wait_for(loop.sock_connect(sock, sockaddr), timeout=PROBE_TIMEOUT_S)
        except (asyncio.TimeoutError, OSError):
            return False
        try:
            await asyncio.wait_for(loop.sock_sendall(sock, request), timeout=PROBE_TIMEOUT_S)
        except (asyncio.TimeoutError, OSError):
            return False
        buf = b""
        try:
            while True:
                chunk = await asyncio.wait_for(
                    loop.sock_recv(sock, 4096), timeout=PROBE_TIMEOUT_S,
                )
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 65536:
                    break
        except (asyncio.TimeoutError, OSError):
            return False
    finally:
        try:
            sock.close()
        except OSError:
            pass

    # Parse minimal HTTP/1.x response: status line + headers + optional body.
    head, _, body = buf.partition(b"\r\n\r\n")
    first_line = head.split(b"\r\n", 1)[0]
    parts = first_line.split(b" ", 2)
    if len(parts) < 2:
        return False
    try:
        status = int(parts[1])
    except ValueError:
        return False
    if status != expected_status:
        return False
    if expected_body is not None and expected_body not in body:
        return False
    return True


async def detect_captive_portal(timeout=PROBE_TIMEOUT_S):
    """Probe known endpoints in parallel and return a verdict dict.

    Returns:
        {
          "captive": bool,        # True if we appear to be behind a portal
          "probes": {host: ok},   # per-probe verdict
          "open": int,            # how many probes verified open internet
        }

    Conservative semantics: at least 2 probes must verify open for us
    to declare "no portal" -- a single positive could be a hijack
    indistinguishable from a passing portal.
    """
    tasks = {
        host: asyncio.ensure_future(probe_one(host, path, status, body))
        for (host, path, status, body) in PROBES
    }
    try:
        await asyncio.wait_for(
            asyncio.gather(*tasks.values(), return_exceptions=True),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        for t in tasks.values():
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks.values(), return_exceptions=True)

    probes = {}
    open_count = 0
    for host, t in tasks.items():
        ok = False
        if t.done() and not t.cancelled():
            try:
                ok = bool(t.result())
            except Exception:  # noqa: BLE001 -- treat any error as "didn't verify"
                ok = False
        probes[host] = ok
        if ok:
            open_count += 1

    # 2-of-N quorum.  A single positive is too easy to fake / hijack;
    # demanding 2 protects against one portal that happens to mimic
    # one of our canary signatures correctly.
    captive = open_count < 2

    if captive:
        log(fstr(
            "captive_portal: VERDICT captive=True open={0}/{1} probes={2}",
            (open_count, len(PROBES), probes),
        ))
    else:
        log(fstr(
            "captive_portal: VERDICT open open={0}/{1}",
            (open_count, len(PROBES)),
        ))

    return {
        "captive": captive,
        "probes": probes,
        "open": open_count,
    }
