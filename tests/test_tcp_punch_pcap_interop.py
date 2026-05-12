"""Asymmetric interop microbench: kernel-TCP <-> pcap-userspace simul-open.

This test is the on-host gate for the pcap_experiment merge decision.
The XP cross-NAT tcp_punch_pcap plugin can only ship when a peer
running it can successfully simul-open against a peer running the
LEGACY kernel-stack tcp_punch.  Pcap-vs-pcap is not enough -- the
merge target (ai_experiment) doesn't run the pcap plugin on any
non-XP host, so every production interop pairing is asymmetric.

What this exercises:
    Process A (initiator): legacy `tcp_punch_engine.bind_tcp_sockets`
        + `connect_on_tcp_sockets` -- the exact code path a Fedora /
        Linux / Vista+ peer runs in production.  Real kernel SOCK_STREAM
        sockets, real bind, real connect_ex SYN spray.

    Process B (responder): tcp_punch_pcap's userspace stack
        (`aionetiface.net.pcap.tcp.conn.Connection`).  Reads frames
        through libpcap, drives the SYN/SYN+ACK/ACK simul-open dance
        in userspace, injects outgoing frames via pcap inject.  No
        kernel TCP involvement on this side.

How the two halves can actually exchange packets without the host
kernel intercepting them:
    Two Linux network namespaces connected by a veth pair.  nsA gets
    198.51.100.1/24 on veth0; nsB gets 198.51.100.2/24 on veth1.
    Process A runs in nsA (default for this test process); process
    B runs in nsB via `nsenter`.  In nsB we install an iptables
    OUTPUT DROP rule for tcp --tcp-flags RST RST so the nsB kernel
    can't shoot down process B's userspace handshake before pcap
    captures the inbound SYN.  (Process B's userspace stack uses
    a TEST-NET-2 source IP that the kernel does own -- nsB's veth1
    -- so unsolicited inbound SYNs to that IP would normally produce
    a kernel RST.  Hence the DROP rule.)

    No global sudo required: Linux unprivileged user namespaces
    (`unshare -Urn`) provide enough capability inside the namespace
    to create veth pairs, install iptables rules, and bind to any
    port without touching the host's real network state.

Skip conditions:
    - non-Linux platform (Windows / BSD / macOS): netns + iptables
      aren't applicable; the production path on those hosts is the
      legacy kernel stack anyway.
    - /proc/sys/kernel/unprivileged_userns_clone reads 0 (Debian-
      family default before bookworm): no way to build the
      topology without root.
    - libpcap not importable / no permission inside nsB.

The kernel stack legacy engine is well-tested; if this asymmetric
microbench fails, the bug is almost certainly in tcp_punch_pcap's
userspace simul-open path -- the same area covered by
test_pcap_live_loopback (in-process) and test_pcap_state (unit-level
state machine), but with real cross-process timing and kernel-issued
SYNs on the wire.

Wall-clock coordination:
    Both halves write a READY sentinel to a shared tmpdir mailbox and
    wait for the other's.  Once both are present they wait until a
    pre-agreed wall-clock punch time (mailbox-held), then fire.  No
    NTP -- both processes run on the same host, so monotonic clocks
    suffice with a small absolute-time bias.
"""
import asyncio
import multiprocessing
import os
import shutil
import socket as stdlib_socket
import subprocess
import sys
import tempfile
import time
import unittest

from aionetiface.testing import AsyncTestCase


# TEST-NET-2 addresses (RFC 5737).  Chosen so even if the host happens
# to have global routes to .0/24 they won't conflict inside the netns
# (the netns has its own routing table).
NSA_IP = "198.51.100.1"
NSB_IP = "198.51.100.2"
SUBNET = "198.51.100.0/24"

# Punch port pair.  High ephemeral range, far from anything the host
# kernel allocator will pick on its own.
INITIATOR_PORT = 47201
RESPONDER_PORT = 47202

# Round-trip payload size requested by the merge gate.
PAYLOAD_A_TO_B = bytes(bytearray((i * 7 + 11) % 251 for i in range(1024)))
PAYLOAD_B_TO_A = bytes(bytearray((i * 13 + 5) % 251 for i in range(1024)))

# Wall-clock offset from "both READY" until both halves fire.  Big enough
# to absorb scheduler jitter, small enough to keep the test snappy.
PUNCH_OFFSET_S = 1.5

# Hard ceiling per worker before the parent SIGKILLs it and fails.
WORKER_TIMEOUT_S = 25.0

# Env-var sentinel: we re-exec ourselves under `unshare -Urn` if it isn't
# set.  When set, we know we're already inside the new user+net ns.
NETNS_READY_ENV = "WARPGATE_PCAP_INTEROP_NETNS"


def have_unprivileged_userns():
    """True iff the kernel permits unprivileged userns creation."""
    try:
        with open("/proc/sys/kernel/unprivileged_userns_clone", "r") as f:
            return f.read().strip() == "1"
    except FileNotFoundError:
        # Kernels without that sysctl (RHEL-family) default to enabled
        # when user namespaces are compiled in; probe by trying.
        return True
    except OSError:
        return False


def have_tools():
    """All shell tools we shell out to must be present."""
    for tool in ("unshare", "nsenter", "ip", "iptables"):
        if shutil.which(tool) is None:
            return False, tool
    return True, None


def run_cmd(args, check=True):
    """Run a shell command, surfacing stdout+stderr in test failure logs.

    Returns the CompletedProcess.  Raises RuntimeError on non-zero exit
    when check=True so the test fails loudly rather than silently
    proceeding past a missing veth.
    """
    proc = subprocess.run(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    out = proc.stdout.decode("utf-8", "replace").strip()
    err = proc.stderr.decode("utf-8", "replace").strip()
    print("[netns-setup] {0} -> rc={1} out={2!r} err={3!r}".format(
        " ".join(args), proc.returncode, out, err,
    ))
    if check and proc.returncode != 0:
        raise RuntimeError("netns setup cmd failed: " + " ".join(args)
                           + " stderr=" + err)
    return proc


def write_atomic(path, content):
    """Same rename-after-write pattern as the pcap-vs-pcap microbench."""
    tmp = path + ".tmp"
    data = content if isinstance(content, bytes) else content.encode("utf-8")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.rename(tmp, path)


def wait_for_file(path, timeout_s):
    """Poll a sentinel file at 20 Hz."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if os.path.exists(path):
            return True
        time.sleep(0.05)
    return False


# --- INITIATOR (kernel TCP) ---------------------------------------------

def initiator_main(mailbox_dir):
    """Run in a fresh subprocess in nsA.  Uses the legacy tcp_punch
    engine helpers directly -- no auto_connect / Node / signal
    channel: this is a unit-level exercise of the engine's
    bind-and-spray path against a real cross-process peer.
    """
    result_path = os.path.join(mailbox_dir, "result_initiator.txt")
    try:
        outcome = initiator_inner(mailbox_dir)
    except Exception as exc:
        outcome = "fail: initiator raised " + repr(exc)
    try:
        write_atomic(result_path, outcome)
    except OSError:
        pass
    print("interop initiator: " + outcome)


def initiator_inner(mailbox_dir):
    """The actual kernel-TCP simul-open spray, identical in spirit to
    what auto_connect runs in production on a non-XP peer."""
    # Import lazily so import failures attach to the worker's result
    # file rather than crashing test collection.
    sys.path.insert(0, "/home/x/projects/warpgate/src")
    sys.path.insert(0, "/home/x/projects/aionetiface/src")
    from warpgate.traversal.plugins.tcp_punch.tcp_punch_utils import (
        bind_tcp_sockets, connect_on_tcp_sockets,
    )
    from warpgate.traversal.plugins.tcp_punch.tcp_punch_engine import (
        socket_event_monitor,
    )
    from warpgate.traversal.plugins.tcp_punch.punch_defs import PortAlloc
    import selectors

    # Hand-built PortAlloc: one src/dest pair only (NUM_PORTS=1 here).
    # The legacy engine handles any number; we keep it to one so the
    # microbench can assert exactly one ESTABLISHED kernel socket.
    allocs = [PortAlloc(INITIATOR_PORT, RESPONDER_PORT)]

    # Bind via the legacy helper (sock_opt_voodoo, SO_LINGER 0,
    # SO_REUSEADDR/SO_REUSEPORT on POSIX, etc).
    bound = bind_tcp_sockets(
        af=stdlib_socket.AF_INET,
        nic_id=None,
        port_allocs=allocs,
        src_ip=NSA_IP,
        route=None,
    )
    if not bound:
        return "fail: bind_tcp_sockets returned empty list"
    if len(bound) != 1:
        return "fail: expected 1 bound socket, got {0}".format(len(bound))

    # Register the bound socket with a selector before connect so we
    # don't miss the SYN-ACK / matching SYN that arrives microseconds
    # after connect_ex returns.
    sel = selectors.DefaultSelector()
    for pa, s in bound:
        s.setblocking(False)
        sel.register(s, selectors.EVENT_WRITE | selectors.EVENT_READ)

    # Mailbox handshake -- announce READY, wait for peer's, read the
    # negotiated punch_time the parent dropped into the mailbox.
    write_atomic(os.path.join(mailbox_dir, "ready_initiator.txt"), "go")
    if not wait_for_file(os.path.join(mailbox_dir, "ready_responder.txt"), 15.0):
        return "fail: responder never wrote READY"
    punch_at_path = os.path.join(mailbox_dir, "punch_at.txt")
    if not wait_for_file(punch_at_path, 5.0):
        return "fail: parent never wrote punch_at"
    with open(punch_at_path, "r") as f:
        punch_at = float(f.read().strip())

    # Sleep until punch time (wall-clock, both procs use time.time()).
    now = time.time()
    if punch_at > now:
        time.sleep(punch_at - now)

    # Spray SYNs.  same_machine=True for the netns-loopback path -- no
    # RTT slack so we want flat-out connect_ex iteration like the
    # in-process LAN tests do.  Cap the spray to 3 s; the userspace
    # peer takes <100 ms to converge once both fire.
    connect_on_tcp_sockets(
        same_machine=True, bound_infos=bound, dest_ip=NSB_IP,
        spray_duration=3.0,
    )
    successful = socket_event_monitor(
        sel, monitor_duration=3.0, retry_interval=0.05,
    )

    # Close every losing socket; keep at most one for I/O.
    winning_sock = None
    for pa, s in bound:
        if s in successful and winning_sock is None:
            winning_sock = s
        else:
            try:
                s.close()
            except OSError:
                pass
    sel.close()

    if winning_sock is None:
        return "fail: monitor reported no ESTABLISHED sockets"

    # Confirm kernel agrees we are connected.
    try:
        peer = winning_sock.getpeername()
    except OSError as exc:
        try:
            winning_sock.close()
        except OSError:
            pass
        return "fail: getpeername raised " + repr(exc)
    if peer[0] != NSB_IP or peer[1] != RESPONDER_PORT:
        try:
            winning_sock.close()
        except OSError:
            pass
        return "fail: peer addr {0} != expected ({1}, {2})".format(
            peer, NSB_IP, RESPONDER_PORT,
        )

    # Round-trip.  Initiator sends first, then reads echo.
    winning_sock.setblocking(True)
    winning_sock.settimeout(8.0)
    try:
        winning_sock.sendall(PAYLOAD_A_TO_B)
    except OSError as exc:
        try:
            winning_sock.close()
        except OSError:
            pass
        return "fail: sendall A->B raised " + repr(exc)

    recv_buf = bytearray()
    deadline = time.time() + 8.0
    while len(recv_buf) < len(PAYLOAD_B_TO_A) and time.time() < deadline:
        try:
            chunk = winning_sock.recv(2048)
        except OSError as exc:
            return "fail: recv B->A raised " + repr(exc)
        if not chunk:
            break
        recv_buf.extend(chunk)

    if bytes(recv_buf) != PAYLOAD_B_TO_A:
        try:
            winning_sock.close()
        except OSError:
            pass
        return "fail: B->A mismatch got={0} expected={1}".format(
            len(recv_buf), len(PAYLOAD_B_TO_A),
        )

    try:
        winning_sock.close()
    except OSError:
        pass
    return "ok"


# --- RESPONDER (pcap userspace) -----------------------------------------

def responder_main(mailbox_dir, iface_name):
    """Run in a fresh subprocess in nsB (entered via nsenter).
    Drives the userspace pcap TCP stack.
    """
    result_path = os.path.join(mailbox_dir, "result_responder.txt")
    try:
        outcome = responder_inner(mailbox_dir, iface_name)
    except Exception as exc:
        outcome = "fail: responder raised " + repr(exc)
    try:
        write_atomic(result_path, outcome)
    except OSError:
        pass
    print("interop responder: " + outcome)


def responder_inner(mailbox_dir, iface_name):
    sys.path.insert(0, "/home/x/projects/warpgate/src")
    sys.path.insert(0, "/home/x/projects/aionetiface/src")
    from aionetiface.entrypoint import aionetiface_setup_event_loop
    aionetiface_setup_event_loop()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(responder_coro(mailbox_dir, iface_name))
    finally:
        try:
            loop.close()
        except Exception:
            pass


async def responder_coro(mailbox_dir, iface_name):
    from aionetiface.net.pcap import (
        get_backend, PcapUnavailableError, PcapError,
    )
    from aionetiface.net.pcap.tcp.conn import Connection, ConnectionError2

    try:
        factory = get_backend()
    except PcapUnavailableError as exc:
        return "skip: pcap unavailable: " + str(exc)
    if not factory.available():
        return "skip: pcap factory not available"
    try:
        backend = factory.open(iface_name, timeout_ms=10)
    except PcapError as exc:
        return "skip: pcap_open_live(" + iface_name + ") failed: " + str(exc)
    try:
        try:
            backend.set_filter(
                "tcp and port {0} and port {1}".format(
                    RESPONDER_PORT, INITIATOR_PORT))
        except PcapError:
            pass

        # READY + punch_at handshake.
        write_atomic(os.path.join(mailbox_dir, "ready_responder.txt"), "go")
        if not wait_for_file(os.path.join(mailbox_dir, "ready_initiator.txt"), 15.0):
            return "fail: initiator never wrote READY"
        punch_at_path = os.path.join(mailbox_dir, "punch_at.txt")
        if not wait_for_file(punch_at_path, 5.0):
            return "fail: parent never wrote punch_at"
        with open(punch_at_path, "r") as f:
            punch_at = float(f.read().strip())

        now = time.time()
        if punch_at > now:
            await asyncio.sleep(punch_at - now)

        conn = Connection(backend, NSB_IP)
        await conn.start_active(
            remote_ip=NSA_IP,
            remote_port=INITIATOR_PORT,
            local_port=RESPONDER_PORT,
            simul=True,
        )
        try:
            await conn.wait_established(timeout=8.0)
        except ConnectionError2 as exc:
            try:
                await conn.close()
            except Exception:
                pass
            return "fail: wait_established raised " + repr(exc)
        except asyncio.TimeoutError:
            try:
                await conn.close()
            except Exception:
                pass
            return "fail: wait_established timed out"

        # Round-trip.  Responder receives A->B first, then sends B->A.
        rx = bytearray()
        deadline = asyncio.get_event_loop().time() + 8.0
        while len(rx) < len(PAYLOAD_A_TO_B):
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            try:
                chunk = await conn.recv(2048, timeout=remaining)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            rx.extend(chunk)
        if bytes(rx) != PAYLOAD_A_TO_B:
            try:
                await conn.close()
            except Exception:
                pass
            return "fail: A->B mismatch got={0} expected={1}".format(
                len(rx), len(PAYLOAD_A_TO_B),
            )
        try:
            await conn.send(PAYLOAD_B_TO_A)
        except ConnectionError2 as exc:
            try:
                await conn.close()
            except Exception:
                pass
            return "fail: send B->A raised " + repr(exc)
        # Give the userspace stack time to flush before close.
        await asyncio.sleep(0.5)
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


# --- DRIVER (the AsyncTestCase) -----------------------------------------

class TestPcapPunchInterop(AsyncTestCase):
    """Asymmetric kernel-TCP <-> pcap-userspace simul-open.

    See module docstring for the setup story.  This single test class
    holds one test_method because the netns + veth + iptables setup
    is a per-method overhead worth ~50 ms but the actual simul-open
    is the load-bearing assertion.
    """

    async def asyncSetUp(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("netns/veth setup is Linux-only")
        if not have_unprivileged_userns():
            self.skipTest(
                "unprivileged userns disabled; "
                "set /proc/sys/kernel/unprivileged_userns_clone=1 to enable"
            )
        ok, missing = have_tools()
        if not ok:
            self.skipTest("missing required tool: " + missing)
        # Re-exec under `unshare -Urn` if we're not already inside a
        # user+net namespace.  The env var sentinel is checked first so
        # the re-execed self doesn't recurse.
        if os.environ.get(NETNS_READY_ENV) != "1":
            self.skipTest(
                "test must be run under `unshare -Urn`; "
                "use run script or `unshare -Urn python -m unittest "
                "tests.test_tcp_punch_pcap_interop` (the test runner "
                "wrapper sets " + NETNS_READY_ENV + "=1)"
            )

        # Probe pcap backend availability before doing any expensive
        # setup -- if libpcap is missing we want a clean skip, not
        # half-built veth state to tear down.
        try:
            from aionetiface.net.pcap import get_backend, PcapUnavailableError
        except ImportError as exc:
            self.skipTest("aionetiface.net.pcap import failed: " + repr(exc))
        try:
            factory = get_backend()
        except PcapUnavailableError as exc:
            self.skipTest("pcap unavailable: " + str(exc))
        if not factory.available():
            self.skipTest("pcap factory not available")

        self.tmpdir = tempfile.mkdtemp(prefix="pcap_interop_")
        self.nsb_holder = None
        self.iptables_applied = False
        await self.build_topology()

    async def build_topology(self):
        """Create veth0/veth1, second netns, iptables drop-RST."""
        # Spawn a long-lived child that holds nsB's netns alive while
        # the test runs.  `unshare --net sleep` is the canonical idiom
        # -- the child's /proc/<pid>/ns/net fd is the handle we use to
        # set veth1's netns and to nsenter into.
        self.nsb_holder = subprocess.Popen(
            ["unshare", "--net", "sleep", str(int(WORKER_TIMEOUT_S * 3))]
        )
        # Brief wait for unshare(NEWNET) to take effect inside the
        # child; without this `ip link ... netns <pid>` can race the
        # child's namespace setup and migrate veth1 into the parent's
        # net ns instead.
        time.sleep(0.2)
        pid = self.nsb_holder.pid

        # nsA setup (we are nsA).
        run_cmd(["ip", "link", "set", "lo", "up"])
        run_cmd([
            "ip", "link", "add", "veth0",
            "type", "veth", "peer", "name", "veth1", "netns", str(pid),
        ])
        run_cmd(["ip", "addr", "add", NSA_IP + "/24", "dev", "veth0"])
        run_cmd(["ip", "link", "set", "veth0", "up"])

        # nsB setup (via nsenter).
        run_cmd(["nsenter", "-t", str(pid), "-n", "ip", "link", "set", "lo", "up"])
        run_cmd(["nsenter", "-t", str(pid), "-n",
                 "ip", "addr", "add", NSB_IP + "/24", "dev", "veth1"])
        run_cmd(["nsenter", "-t", str(pid), "-n",
                 "ip", "link", "set", "veth1", "up"])

        # Block nsB's kernel from RSTing the inbound SYN it gets at
        # 198.51.100.2:RESPONDER_PORT.  Without this rule the SYN that
        # process A's kernel emits would land on nsB, find no kernel
        # socket bound, and bounce back as a RST -- killing process
        # A's connect() before pcap can answer.
        run_cmd(["nsenter", "-t", str(pid), "-n",
                 "iptables", "-A", "OUTPUT", "-p", "tcp",
                 "--tcp-flags", "RST", "RST", "-j", "DROP"])
        self.iptables_applied = True

        # Sanity ping.  Both kernels still have ICMP enabled; if this
        # fails the topology is broken before we even start.
        run_cmd(["ping", "-c", "1", "-W", "2", NSB_IP])

    async def asyncTearDown(self):
        # Tear down the nsB holder; veth pair dies with the netns.
        if self.nsb_holder is not None:
            try:
                self.nsb_holder.terminate()
                self.nsb_holder.wait(timeout=3.0)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    self.nsb_holder.kill()
                except OSError:
                    pass
        # Mailbox cleanup -- best-effort.
        if hasattr(self, "tmpdir") and self.tmpdir:
            try:
                for name in os.listdir(self.tmpdir):
                    try:
                        os.unlink(os.path.join(self.tmpdir, name))
                    except OSError:
                        pass
                os.rmdir(self.tmpdir)
            except OSError:
                pass

    async def test_kernel_vs_pcap_simul_open(self):
        """The asymmetric merge gate.  Both halves must reach
        ESTABLISHED and complete a 1024-byte bidirectional round-trip.
        """
        # Pre-publish the wall-clock punch time before launching the
        # workers so they don't race on the file.
        punch_at = time.time() + PUNCH_OFFSET_S
        write_atomic(os.path.join(self.tmpdir, "punch_at.txt"),
                     "{0:.6f}".format(punch_at))

        # Initiator runs in our own netns (nsA) via multiprocessing.
        # "spawn" is the default per aionetiface_setup_event_loop's
        # multiprocessing.set_start_method.
        ctx = multiprocessing.get_context("spawn")
        initiator = ctx.Process(
            target=initiator_main, args=(self.tmpdir,),
        )
        initiator.start()

        # Responder runs in nsB.  We can't multiprocessing-spawn into
        # a different netns from inside Python (the child inherits our
        # net ns at fork-time), so we exec a fresh interpreter under
        # nsenter and have it import + dispatch to responder_main.
        responder_runner = """
import sys
sys.path.insert(0, '{warpgate_src}')
sys.path.insert(0, '{aio_src}')
sys.path.insert(0, '{tests_dir}')
from test_tcp_punch_pcap_interop import responder_main
responder_main({mailbox!r}, {iface!r})
""".format(
            warpgate_src="/home/x/projects/warpgate/src",
            aio_src="/home/x/projects/aionetiface/src",
            tests_dir="/home/x/projects/warpgate/tests",
            mailbox=self.tmpdir,
            iface="veth1",
        )
        responder = subprocess.Popen(
            ["nsenter", "-t", str(self.nsb_holder.pid), "-n",
             sys.executable, "-c", responder_runner],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

        # Wait for both with a generous timeout.  If either side hangs
        # past WORKER_TIMEOUT_S we fail the test rather than letting
        # the test runner SIGKILL the whole subprocess.
        deadline = time.time() + WORKER_TIMEOUT_S
        initiator.join(timeout=max(0.1, deadline - time.time()))
        try:
            r_out, r_err = responder.communicate(
                timeout=max(0.1, deadline - time.time()))
        except subprocess.TimeoutExpired:
            responder.kill()
            r_out, r_err = responder.communicate(timeout=3.0)

        if initiator.is_alive():
            initiator.terminate()
            initiator.join(timeout=2.0)
            self.fail("initiator did not exit within "
                      + str(WORKER_TIMEOUT_S) + "s")

        # Capture responder stdout/stderr verbatim into the test log so
        # any traceback or pcap-library error is visible if assertion
        # fails.
        print("=== responder stdout ===")
        print(r_out.decode("utf-8", "replace") if r_out else "")
        print("=== responder stderr ===")
        print(r_err.decode("utf-8", "replace") if r_err else "")
        print("========================")

        outcomes = {}
        for role in ("initiator", "responder"):
            path = os.path.join(self.tmpdir, "result_" + role + ".txt")
            if not os.path.exists(path):
                self.fail(
                    "worker " + role + " left no result file -- "
                    "crashed before writing outcome")
            with open(path, "rb") as f:
                outcomes[role] = f.read().decode("utf-8", "replace")

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
