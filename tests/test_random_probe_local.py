"""
Local end-to-end test for the random-probe rendezvous algorithm.

We can't conjure an actual symmetric NAT inside a single process,
but we *can* model the algorithm exactly: the cone side fires N
random destination ports at the symmetric side's external IP, and
the symmetric side fires one probe from each of N source-port-
distinct sockets at the cone's known (ext_ip, ext_port).  When the
two range-overlap correctly, one of the cone's destination ports
matches one of the symmetric's bound source ports and the
symmetric host's listening socket on that port receives a real
inbound probe -- the same outcome a real (cone, sym) pair would
produce on the wire.

Skipped on platforms that don't alias 127.0.0.x (macOS by default)
since we need two distinct loopback IPs to keep the cone and
symmetric sides cleanly separated.

Lives in its own file (per CLAUDE.md "Heavy tests live in their
own file") so the runner gives the round-trip a fresh subprocess
and other tests' UDP socket state can't bleed into it.
"""

import asyncio
import os
import unittest

from aionetiface.testing import AsyncTestCase, probe_loopback_ips

from p2pd.traversal.plugins.random_probe.random_probe_lib import (
    recvfrom_async,
    run_non_sym_side,
    run_symmetric_side,
)


# Bigger than DEFAULT_PROBE_COUNT to push the success rate to ~99%
# in a single try -- this test runs in CI and we don't want a
# birthday-paradox roll of the dice to flake the matrix.
PROBE_COUNT = 512


class TestRandomProbeLocal(AsyncTestCase):
    """Cone + symmetric run in parallel and converge on a usable 4-tuple."""

    async def asyncSetUp(self):
        ips = probe_loopback_ips(max_count=4)
        if len(ips) < 2:
            self.skipTest(
                "need two bindable 127.0.0.x aliases (got {0}); "
                "platform doesn't support loopback aliasing".format(ips)
            )
        self.cone_ip = ips[0]
        self.sym_ip = ips[1]

    async def test_collision_produces_4tuple(self):
        nonce = os.urandom(16)

        # Use the same RNG seed for both sides so the test is
        # deterministic *and* the probe-port range overlaps every
        # time -- the algorithm itself is non-deterministic in
        # production (SystemRandom), but for the unit-level proof
        # we want repeatability.
        import random
        rng_a = random.Random(0xC0DE)
        rng_b = random.Random(0xC0DE ^ 0xFFFF)

        # Cone known port = pick something in the probe range so
        # both sides' RNGs can plausibly pick it.  The sym side
        # fires *to* this port; it doesn't have to be in the
        # probe-port range, but the cone needs to bind it.
        cone_known_port = 49213

        cone_task = asyncio.ensure_future(run_non_sym_side(
            bind_ip=self.cone_ip,
            known_port=cone_known_port,
            peer_ext_ip=self.sym_ip,
            nonce=nonce,
            probe_count=PROBE_COUNT,
            listen_timeout=6,
            rng=rng_a,
        ))
        sym_task = asyncio.ensure_future(run_symmetric_side(
            bind_ip=self.sym_ip,
            cone_ext_ip=self.cone_ip,
            cone_ext_port=cone_known_port,
            nonce=nonce,
            probe_count=PROBE_COUNT,
            listen_timeout=6,
            rng=rng_b,
        ))

        try:
            cone_res, sym_res = await asyncio.wait_for(
                asyncio.gather(cone_task, sym_task),
                timeout=10,
            )
        except asyncio.TimeoutError:
            cone_task.cancel()
            sym_task.cancel()
            self.fail("random-probe round-trip timed out")

        try:
            self.assertIsNotNone(
                cone_res, "cone side received no probe from symmetric side",
            )
            self.assertIsNotNone(
                sym_res, "symmetric side received no probe from cone side",
            )

            self.assertEqual(cone_res["role"], "non_sym")
            self.assertEqual(sym_res["role"], "sym")

            # The cone side saw the symmetric peer at *some* (ip, port)
            # where the IP is the symmetric side's bind IP and the port
            # is one of the symmetric side's source ports.
            self.assertEqual(cone_res["peer"][0], self.sym_ip)

            # The symmetric side saw the cone at exactly the cone's
            # known endpoint -- that's the whole point of the cone
            # being endpoint-independent.
            self.assertEqual(sym_res["peer"], (self.cone_ip, cone_known_port))

            # The CONFIRM-based handshake guarantees both sides
            # agree on the same 4-tuple: the cone only replies to
            # an aligned (src in dst-set) inbound, the sym only
            # locks on the cone's CONFIRM probe.  That means
            # cone_peer == sym_sock.getsockname() and
            # sym_peer == cone_sock.getsockname() -- so a real
            # bidirectional payload exchange should work even in
            # this no-NAT local model.
            cone_sock = cone_res["sock"]
            sym_sock = sym_res["sock"]

            self.assertEqual(
                cone_res["peer"], sym_sock.getsockname(),
                "cone's perceived peer must equal sym winner's bind addr",
            )
            self.assertEqual(
                sym_res["peer"], cone_sock.getsockname(),
                "sym's perceived peer must equal cone winner's bind addr",
            )

            async def poll_recv(sock, want_payload, timeout=3):
                """Poll for a non-probe payload on *sock*.

                Drain any residual probe datagrams (kernel might
                still have late-arriving cone probes queued at
                this sock) and return the first datagram that
                matches *want_payload*.
                """
                deadline = asyncio.get_event_loop().time() + timeout
                while True:
                    try:
                        data, addr = sock.recvfrom(2048)
                    except BlockingIOError:
                        if asyncio.get_event_loop().time() > deadline:
                            return None, None
                        await asyncio.sleep(0.02)
                        continue
                    if data == want_payload:
                        return data, addr

            payload = b"hello-from-cone"
            cone_sock.sendto(payload, cone_res["peer"])
            data, addr = await poll_recv(sym_sock, payload)
            self.assertEqual(data, payload, "sym never received payload from cone")
            self.assertEqual(addr, sym_res["peer"])

            # Reverse direction.
            payload_b = b"hello-from-sym"
            sym_sock.sendto(payload_b, sym_res["peer"])
            data, addr = await poll_recv(cone_sock, payload_b)
            self.assertEqual(data, payload_b, "cone never received payload from sym")
            self.assertEqual(addr, cone_res["peer"])
        finally:
            try:
                cone_res["sock"].close()
            except (OSError, AttributeError, TypeError):
                pass
            try:
                sym_res["sock"].close()
            except (OSError, AttributeError, TypeError):
                pass


if __name__ == "__main__":
    unittest.main()
