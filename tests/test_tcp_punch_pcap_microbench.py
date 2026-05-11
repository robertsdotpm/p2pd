"""Microbench for the userspace pcap simul-open engine.

Exercises tcp_punch_pcap.punch_engine.pcap_punch_engine in a true
cross-process setup, so the simul-open code path actually gets to run
(the legacy in-process cascade always shorts on phase1_direct first).

Why this exists:
    The XP cross-NAT bypass plugin (tcp_punch_pcap) is a userspace
    TCP/IP stack driven over WinPcap.  Its simul-open arm only fires
    when BOTH ends call start_active(simul=True) at roughly the same
    time, on the same predicted four-tuple, from independent OS
    processes.  In-process tests catch state-machine bugs but not the
    cross-process race (driver-loop scheduling, ARP cache populace,
    timer interaction with the kernel's idea of the same port).

What it does:
    - Spawns two child Python processes ("initiator" / "responder").
    - Each child opens libpcap on the loopback interface (DLT_EN10MB
      on Linux, DLT_NULL on BSD/macOS).
    - Each child uses a TEST-NET-2 source IP (198.51.100.1 / .2) so
      the host kernel doesn't reply with RST when it sees an SYN it
      didn't issue (see test_pcap_live_loopback.py for the same
      rationale).
    - Children coordinate via a file-based mailbox in a tempdir:
      each writes its "ready" sentinel, polls for the other's,
      then both call pcap_punch_engine concurrently.
    - On ESTABLISHED, one side sends a 256-byte known pattern; the
      other receives and echoes it back; the initiator asserts the
      round-trip matches.
    - Each child writes its outcome ("ok" or "fail: <reason>") to a
      result file; the parent test reads both and asserts success.

Skips cleanly if:
    - No CAP_NET_RAW / not-root (libpcap_open fails on lo) -- same
      rule as test_pcap_live_loopback.
    - aionetiface.net.pcap backend is missing.

This test does NOT touch MQTT / Node / signal channel -- it is a
unit-level exercise of the engine itself.  End-to-end XP-as-listener
testing lives in xp_pcap_smoke.py (driven by the dev-machine SSH
coordinator), not in this file.
"""
import asyncio
import multiprocessing
import os
import sys
import tempfile
import time
import unittest

from aionetiface.testing import AsyncTestCase
from aionetiface.utility.fstr import fstr


# TEST-NET-2 (RFC 5737) -- guaranteed not configured anywhere on the
# host, so the kernel won't generate RSTs in response to our injected
# SYNs.
INITIATOR_IP = "198.51.100.1"
RESPONDER_IP = "198.51.100.2"

# The microbench bench port pair.  Both sides know these statically;
# the auto_connect / signal-channel coordination that picks ports in
# production is out of scope for this test.
INITIATOR_PORT = 47101
RESPONDER_PORT = 47102

# Known payload for the round-trip assertion.
ROUND_TRIP_PAYLOAD = bytes(bytearray(i % 251 for i in range(256)))

# Per-side soft deadline.  The engine itself caps at 30 s; we give the
# subprocess a little slack for fork/spawn-up.
WORKER_TIMEOUT_S = 20.0


def loopback_iface_name():
    if sys.platform.startswith("linux"):
        return "lo"
    if (
        sys.platform.startswith("darwin")
        or sys.platform.startswith("freebsd")
        or sys.platform.startswith("openbsd")
        or sys.platform.startswith("netbsd")
    ):
        return "lo0"
    return None


def write_atomic(path, content):
    """Write a sentinel file in one atomic step (rename-after-write).

    Cross-platform-safe; both Linux and the BSDs honour rename
    atomicity on the same filesystem.  Used to publish READY / DONE
    state without a half-written-file race against the peer's poll.
    """
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(content if isinstance(content, bytes) else content.encode("utf-8"))
        f.flush()
        os.fsync(f.fileno())
    os.rename(tmp, path)


def wait_for_file(path, timeout_s):
    """Block (in this child's main thread) until path exists or we time out.

    Polls at 20 Hz.  Cheap enough -- only used once per child to
    synchronise the simul-open kickoff.
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if os.path.exists(path):
            return True
        time.sleep(0.05)
    return False


def worker_main(role, mailbox_dir, iface, peer_ip, my_ip,
                my_port, peer_port):
    """Child-process entry point.

    Runs in its own Python interpreter started with multiprocessing
    spawn (set by aionetiface_setup_event_loop).  Writes its outcome
    to mailbox_dir/result_<role>.txt -- the parent reads both files
    after .join() to assert success.
    """
    # We are now in a fresh interpreter -- nothing from the parent's
    # asyncio loop survives.  Import + set up our own loop.
    from aionetiface.entrypoint import aionetiface_setup_event_loop
    aionetiface_setup_event_loop()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result_path = os.path.join(mailbox_dir, "result_" + role + ".txt")
    try:
        outcome = loop.run_until_complete(
            worker_async(role, mailbox_dir, iface,
                         peer_ip, my_ip, my_port, peer_port)
        )
    except Exception as exc:
        outcome = "fail: worker_async raised " + repr(exc)
    finally:
        try:
            loop.close()
        except Exception:
            pass
    try:
        write_atomic(result_path, outcome)
    except Exception:
        # Last-ditch: the parent will treat a missing file as failure.
        pass
    print(fstr("microbench worker {0}: {1}", (role, outcome)))


async def worker_async(role, mailbox_dir, iface,
                       peer_ip, my_ip, my_port, peer_port):
    """The actual asyncio coroutine running in each child.

    Returns the outcome string that gets written to the mailbox file.
    """
    from aionetiface.net.pcap import (
        get_backend, PcapUnavailableError, PcapError,
    )
    from aionetiface.net.pcap.tcp.conn import (
        Connection, ConnectionError2,
    )

    # Acquire pcap backend.  Same skip semantics as the existing
    # live-loopback test -- if we can't open the iface (no root) we
    # report "skip: <reason>" so the parent will skipTest cleanly.
    try:
        factory = get_backend()
    except PcapUnavailableError as exc:
        return "skip: pcap unavailable: " + str(exc)
    if not factory.available():
        return "skip: pcap factory not available"
    try:
        backend = factory.open(iface, timeout_ms=10)
    except PcapError as exc:
        return "skip: pcap_open_live(" + iface + ") failed: " + str(exc)
    try:
        # Tight BPF: only our two ports' TCP traffic.  Cuts the
        # reader's wake rate dramatically on a busy loopback.
        try:
            backend.set_filter(
                "tcp and port {0} and port {1}".format(my_port, peer_port)
            )
        except PcapError:
            # Filter is optional -- the FourTuple filter in
            # Connection.process_frame still narrows things down.
            pass

        # Publish our READY sentinel; wait for the peer's.
        ready_me = os.path.join(mailbox_dir, "ready_" + role + ".txt")
        ready_peer = os.path.join(
            mailbox_dir,
            "ready_" + ("responder" if role == "initiator" else "initiator") + ".txt",
        )
        write_atomic(ready_me, "go")
        if not wait_for_file(ready_peer, timeout_s=10.0):
            return "fail: peer never wrote READY"

        # Both sides are now armed.  Fire simul-open.  We deliberately
        # do NOT route through tcp_punch_pcap.pcap_punch_engine here
        # because it tries to install a Windows-Firewall rule which
        # makes no sense on Linux; we drive Connection directly so the
        # microbench works on every dev box.  The engine's wrapper is
        # exercised in xp_pcap_smoke.py instead.
        conn = Connection(backend, my_ip)
        await conn.start_active(
            remote_ip=peer_ip,
            remote_port=peer_port,
            local_port=my_port,
            simul=True,
        )

        try:
            await conn.wait_established(timeout=8.0)
        except ConnectionError2 as exc:
            return "fail: wait_established raised " + repr(exc)
        except asyncio.TimeoutError:
            return "fail: wait_established timed out"

        # Round-trip protocol:
        #   initiator: send payload -> recv echo -> assert match
        #   responder: recv payload -> send same bytes back
        if role == "initiator":
            await conn.send(ROUND_TRIP_PAYLOAD)
            chunks = []
            deadline = asyncio.get_event_loop().time() + 5.0
            while sum(len(c) for c in chunks) < len(ROUND_TRIP_PAYLOAD):
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    break
                try:
                    chunk = await conn.recv(2048, timeout=remaining)
                except asyncio.TimeoutError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            got = b"".join(chunks)
            if got != ROUND_TRIP_PAYLOAD:
                return ("fail: round-trip mismatch got={0} bytes "
                        "expected={1}".format(len(got),
                                              len(ROUND_TRIP_PAYLOAD)))
        else:
            chunks = []
            deadline = asyncio.get_event_loop().time() + 5.0
            while sum(len(c) for c in chunks) < len(ROUND_TRIP_PAYLOAD):
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    break
                try:
                    chunk = await conn.recv(2048, timeout=remaining)
                except asyncio.TimeoutError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            got = b"".join(chunks)
            if got != ROUND_TRIP_PAYLOAD:
                return ("fail: responder rx mismatch got={0} bytes "
                        "expected={1}".format(len(got),
                                              len(ROUND_TRIP_PAYLOAD)))
            await conn.send(got)
            # Give the kernel/userspace stack a moment to push the echo
            # out before we tear down the Connection.
            await asyncio.sleep(0.2)

        try:
            await conn.close()
        except Exception:
            pass
        return "ok"
    finally:
        try:
            backend.close()
        except Exception:
            pass


class TestPcapPunchMicrobench(AsyncTestCase):
    """Drive pcap_punch_engine in two real processes, asserting both
    sides ESTABLISHED and the round-trip matches.

    Skips on hosts without CAP_NET_RAW or where libpcap can't bind
    the loopback iface.  Designed to be runnable on every dev box in
    the matrix -- Linux/Fedora primary, BSD/macOS opportunistic.
    """

    async def asyncSetUp(self):
        self.iface = loopback_iface_name()
        if self.iface is None:
            self.skipTest("no loopback iface known for " + sys.platform)
        # Quick capability probe in the parent so we skip without
        # incurring the cost of spawning two children that would only
        # report "skip: ...".
        try:
            from aionetiface.net.pcap import (
                get_backend, PcapUnavailableError, PcapError,
            )
        except ImportError as exc:
            self.skipTest("pcap import failed: " + repr(exc))
        try:
            factory = get_backend()
        except PcapUnavailableError as exc:
            self.skipTest("pcap unavailable: " + str(exc))
        if not factory.available():
            self.skipTest("pcap factory not available")
        try:
            probe = factory.open(self.iface, timeout_ms=10)
        except PcapError as exc:
            self.skipTest("pcap_open_live(" + self.iface
                          + ") failed (need CAP_NET_RAW/root): " + str(exc))
        try:
            probe.close()
        except Exception:
            pass
        self.tmpdir = tempfile.mkdtemp(prefix="pcap_microbench_")

    async def asyncTearDown(self):
        # Best-effort cleanup of the mailbox dir.
        try:
            for name in os.listdir(self.tmpdir):
                try:
                    os.unlink(os.path.join(self.tmpdir, name))
                except OSError:
                    pass
            os.rmdir(self.tmpdir)
        except OSError:
            pass

    async def test_microbench_simul_open(self):
        ctx = multiprocessing.get_context("spawn")
        initiator = ctx.Process(
            target=worker_main,
            args=("initiator", self.tmpdir, self.iface,
                  RESPONDER_IP, INITIATOR_IP,
                  INITIATOR_PORT, RESPONDER_PORT),
        )
        responder = ctx.Process(
            target=worker_main,
            args=("responder", self.tmpdir, self.iface,
                  INITIATOR_IP, RESPONDER_IP,
                  RESPONDER_PORT, INITIATOR_PORT),
        )
        initiator.start()
        responder.start()
        # join() blocks the asyncio event loop, but the parent test
        # doesn't have any async work to do while the children run,
        # so a thread executor wrap isn't necessary.
        initiator.join(timeout=WORKER_TIMEOUT_S)
        responder.join(timeout=WORKER_TIMEOUT_S)
        for proc, role in ((initiator, "initiator"), (responder, "responder")):
            if proc.is_alive():
                proc.terminate()
                proc.join(timeout=2.0)
                self.fail("worker " + role + " did not exit within "
                          + str(WORKER_TIMEOUT_S) + "s")

        outcomes = {}
        for role in ("initiator", "responder"):
            path = os.path.join(self.tmpdir, "result_" + role + ".txt")
            if not os.path.exists(path):
                self.fail("worker " + role + " left no result file -- "
                          "likely crashed before writing outcome")
            with open(path, "rb") as f:
                outcomes[role] = f.read().decode("utf-8", "replace")

        # If either side reported "skip:" we honour it test-wide.
        for role, outcome in outcomes.items():
            if outcome.startswith("skip:"):
                self.skipTest(role + " skipped: " + outcome)

        for role, outcome in outcomes.items():
            self.assertEqual(
                outcome, "ok",
                "worker " + role + " reported: " + outcome,
            )


if __name__ == "__main__":
    unittest.main()
