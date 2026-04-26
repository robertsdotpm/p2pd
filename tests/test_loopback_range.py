"""
Platform probe: can we bind / connect to 127.X.Y.Z addresses other
than 127.0.0.1?

The same-machine traversal path picks a per-node 127.X.Y.Z alias from
loopback_ip_for_node(pub_key_hex) and binds the listener on it; the
peer connects to that exact address. On modern OSes (Linux, Windows
Vista+, macOS, *BSD) the kernel routes the entire 127.0.0.0/8 block to
the loopback iface, so any 127.x.x.x bind/connect "just works."

Older Windows -- specifically XP -- has been observed to silently
drop traffic to non-127.0.0.1 loopback aliases even though bind()
succeeds. This test pins down whether the running platform supports
the alias-loopback path. If it doesn't, the matrix can either skip
or fall back to 127.0.0.1 (with port-uniqueness as the only
distinguisher between same-machine peers).

Each subtest uses a different 127.X.Y.Z address to make the matrix
clearer when one ends up working but another doesn't.
"""

import asyncio
import socket
import unittest

from aionetiface.testing import AsyncTestCase


# Three probe addresses spanning the 127.0.0.0/8 block.  127.0.0.1 is
# always-works baseline; the others test whether the platform routes
# the wider range.
PROBE_IPS = [
    "127.0.0.1",
    "127.0.0.2",
    "127.42.7.99",
    "127.250.250.250",
]


async def echo_once(reader, writer):
    """Read until EOF (or 64 bytes) and echo back; close cleanly."""
    try:
        data = await reader.read(64)
        if data:
            writer.write(data)
            await writer.drain()
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def serve_and_roundtrip(addr, payload, timeout=3.0):
    """Bind a TCP server on (addr, 0), connect to it from the same addr,
    send `payload`, expect echo. Returns (ok, error_str)."""
    server = None
    try:
        server = await asyncio.start_server(echo_once, host=addr, port=0)
    except OSError as exc:
        return False, "bind: " + repr(exc)

    bound = server.sockets[0].getsockname()
    bound_port = bound[1]

    try:
        async def client():
            # Bind the connect socket to the same loopback alias so we
            # mirror the in-tree DirectConnect flow (src/dest both 127.*).
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            try:
                sock.bind((addr, 0))
            except OSError as exc:
                sock.close()
                raise OSError("client bind " + addr + ": " + repr(exc))
            loop = asyncio.get_event_loop()
            try:
                await loop.sock_connect(sock, (addr, bound_port))
            except OSError as exc:
                sock.close()
                raise OSError("client connect " + addr + ": " + repr(exc))
            try:
                await loop.sock_sendall(sock, payload)
                got = await loop.sock_recv(sock, len(payload))
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
            return got

        try:
            received = await asyncio.wait_for(client(), timeout=timeout)
        except asyncio.TimeoutError:
            return False, "roundtrip timed out (" + str(timeout) + "s)"
        except OSError as exc:
            return False, str(exc)

        if received != payload:
            return False, "echo mismatch: sent={!r} got={!r}".format(payload, received)
        return True, ""
    finally:
        try:
            server.close()
            await server.wait_closed()
        except Exception:
            pass


class TestLoopbackRangeBindings(AsyncTestCase):
    """Probe the host's behaviour for binding/connecting non-127.0.0.1 loopback IPs."""

    async def test_127_0_0_1_baseline(self):
        ok, err = await serve_and_roundtrip("127.0.0.1", b"baseline")
        if not ok:
            self.fail("127.0.0.1 baseline failed -- platform has no usable loopback: " + err)

    async def test_127_0_0_2_alias(self):
        ok, err = await serve_and_roundtrip("127.0.0.2", b"alias-low")
        if not ok:
            self.skipTest("127.0.0.2 alias not usable on this platform: " + err)

    async def test_127_42_7_99_mid_range(self):
        ok, err = await serve_and_roundtrip("127.42.7.99", b"alias-mid")
        if not ok:
            self.skipTest("127.42.7.99 alias not usable on this platform: " + err)

    async def test_127_250_250_250_high_range(self):
        ok, err = await serve_and_roundtrip("127.250.250.250", b"alias-hi")
        if not ok:
            self.skipTest("127.250.250.250 alias not usable on this platform: " + err)


if __name__ == "__main__":
    unittest.main()
