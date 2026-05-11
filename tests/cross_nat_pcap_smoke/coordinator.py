"""Coordinator for the cross-NAT pcap smoke test.

Runs ON the local dev host (Linux).  Drives the test end-to-end:

  1. Picks two predicted local TCP ports (both in [2024, 52023],
     never 22), one per peer.
  2. Computes a wall-clock punch time (time.time() + PUNCH_OFFSET).
  3. Starts tcpdump on debian-nat for the punch traffic.
  4. SSHes to debian-nat and to the XP VM in parallel, launching
     linux_connector.py and xp_responder.py with matching args.
  5. Captures stdout/stderr from both halves until they exit.
  6. Stops tcpdump, downloads the capture for offline inspection.
  7. Reports outcome based on exit codes + the captured logs.

What this test asserts about the cross-NAT tcp_punch_pcap engine:
    The XP-side pcap stack can complete a TCP simul-open against a
    non-XP kernel-stack peer ACROSS NAT (both sides NATted in this
    setup -- XP at 113.29.240.148, debian-nat at 23.94.29.30).
    Success requires:
      - Both NATs preserve source ports for outbound SYNs (cone NAT
        on each end).  If either NAT is symmetric, the predicted
        destination port won't match the mapping and the punch fails
        without ever seeing a peer SYN.  That's an environment
        failure, not an engine bug.
      - The pcap stack on XP captures the inbound SYN before
        tcpip.sys RSTs it.  This is what the production plugin's
        firewall-block-rule trick was for; here we DON'T install
        the block rule (dispatcher policy forbids host firewall
        mutation), so we measure whether the pcap stack can win
        the race against tcpip.sys on its own.

Three documented outcomes:
    ESTABLISHED + round-trip       -> Win.  Engine works on real
                                      cross-NAT without firewall
                                      help.
    ESTABLISHED briefly then RST   -> Engine completes handshake
                                      but tcpip.sys still RSTs at
                                      ~174 ms.  Firewall mutation
                                      was load-bearing.
    No ESTABLISHED                 -> Either NAT didn't cooperate
                                      (symmetric) or pcap missed
                                      the SYN.  Look at the pcap
                                      to disambiguate.
"""
import argparse
import os
import subprocess
import sys
import threading
import time


# Hosts and credentials.
LOCAL_DEV_HOST = "local"
LINUX_HOST = "debian-nat"
LINUX_USER = None  # baked into ~/.ssh/config for "debian-nat"
LINUX_REPO_P2PD = "/tmp/sweep_repos/p2pd"
LINUX_REPO_AIONETIFACE = "/tmp/sweep_repos/aionetiface"
LINUX_PYTHON = "python3"
LINUX_LAN_IP = "192.168.206.2"  # debian-nat eth0 IP
LINUX_PUBLIC_IP = "23.94.29.30"

XP_HOST = "10.0.1.132"
XP_USER = "matthew"
XP_PUBLIC_IP = "113.29.240.148"
XP_LAN_IP = "10.0.1.132"
XP_PYTHON = r"C:\py3\python.exe"
XP_REPO_P2PD = r"C:\Documents and Settings\matthew\projects\p2pd"
XP_REPO_AIONETIFACE = r"C:\Documents and Settings\matthew\projects\aionetiface"
# Discovered via list_interfaces(); see test setup notes.
XP_PCAP_IFACE = r"\Device\NPF_{11CDC7EA-0716-4C16-878F-6A34B31B6CAF}"

# Predicted ports: in [2024, 52023], not 22, not in a common service
# range that XP's firewall would have an opinion about (5060 / 1900 /
# 445 / 139 / 135 / 5357 etc.).  43201/43202 land in the empty middle.
LINUX_PORT = 43201
XP_PORT = 43202

# Seconds from "now" to "fire" -- enough for SSH login + python boot
# on XP (which is slow), comfortable for both sides to land on the
# wall-clock sleep at the same instant.
PUNCH_OFFSET_S = 12.0

# Hard ceiling per worker before we give up and kill it.
WORKER_TIMEOUT_S = 60.0

# Where to drop artefacts (pcap, per-side stdout).
ARTEFACT_DIR = "/tmp/cross_nat_pcap_smoke"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artefact-dir", default=ARTEFACT_DIR)
    parser.add_argument("--punch-offset", default=PUNCH_OFFSET_S, type=float)
    return parser.parse_args()


def ensure_artefact_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)
    return path


def ssh_cmd(host, user, remote_cmd, port=None):
    """Build an ssh argv that runs remote_cmd on the given host.

    For Windows targets we don't go through a shell wrapper -- ssh's
    default behaviour is to hand the command to cmd.exe on the
    remote side, which is what we want for the XP Python invocation.
    """
    argv = ["ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=15"]
    if port:
        argv.extend(["-p", str(port)])
    if user:
        argv.append("{0}@{1}".format(user, host))
    else:
        argv.append(host)
    argv.append(remote_cmd)
    return argv


def run_remote(name, argv, output_path, ready_event=None):
    """Run a remote command, tee stdout+stderr to a file and the
    console with a per-side prefix, and record the exit code on a
    shared dict.

    `ready_event` is set after Popen returns -- the parent uses it to
    know both subprocesses are launched before computing punch_at.
    """
    print("coordinator: launching {0}: {1}".format(
        name, " ".join(argv[:3] + ["..."])))
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        bufsize=1, universal_newlines=True,
    )
    if ready_event is not None:
        ready_event.set()
    with open(output_path, "w") as out:
        for line in proc.stdout:
            sys.stdout.write("[{0}] {1}".format(name, line))
            sys.stdout.flush()
            out.write(line)
    rc = proc.wait()
    print("coordinator: {0} exited with rc={1}".format(name, rc))
    return rc


def upload_scripts():
    """Copy xp_responder.py and linux_connector.py to their target
    hosts BEFORE we start the workers.  Doing this here keeps the
    test re-runnable: a fresh dispatcher run picks up the latest
    edits without needing a `git pull` step on each VM.

    On debian-nat the repo is reset via dispatcher policy so we
    just rely on the in-repo path.  On XP the repo state might be
    stale; we scp the script to a known location.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    xp_script = os.path.join(here, "xp_responder.py")
    linux_script = os.path.join(here, "linux_connector.py")

    # XP: place the responder under matthew's home dir.
    xp_dest = r"C:\Documents and Settings\matthew\xp_responder.py"
    argv = [
        "scp", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        xp_script,
        "{0}@{1}:{2}".format(XP_USER, XP_HOST, xp_dest),
    ]
    print("coordinator: scp xp_responder.py -> XP")
    rc = subprocess.call(argv)
    if rc != 0:
        raise RuntimeError(
            "scp xp_responder.py to XP failed rc={0}".format(rc))

    # debian-nat: place the connector under /tmp.
    linux_dest = "/tmp/linux_connector.py"
    argv = [
        "scp", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        linux_script,
        "{0}:{1}".format(LINUX_HOST, linux_dest),
    ]
    print("coordinator: scp linux_connector.py -> debian-nat")
    rc = subprocess.call(argv)
    if rc != 0:
        raise RuntimeError(
            "scp linux_connector.py to debian-nat failed rc={0}".format(rc))
    return xp_dest, linux_dest


def start_tcpdump(pcap_path):
    """Launch tcpdump on debian-nat in the background, writing to
    pcap_path on the remote side.  Returns the Popen so the caller
    can kill it after the workers exit.

    We filter on the XP public IP so the capture stays small.
    """
    bpf = "host {0}".format(XP_PUBLIC_IP)
    remote_cmd = (
        "sudo tcpdump -i any -w {0} '{1}' 2>&1"
    ).format(pcap_path, bpf)
    argv = ssh_cmd(LINUX_HOST, LINUX_USER, remote_cmd)
    print("coordinator: starting remote tcpdump -> {0}".format(pcap_path))
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        bufsize=1, universal_newlines=True,
    )
    # Give tcpdump a moment to actually start the capture before
    # the punch fires.  ~2 s is plenty for sshd login + libpcap open.
    time.sleep(2.0)
    return proc


def stop_tcpdump(proc, pcap_path, local_pcap_path):
    """Kill the remote tcpdump cleanly and download the pcap."""
    print("coordinator: stopping remote tcpdump")
    # SIGINT to the ssh client; sshd's signal forwarding to the
    # remote sudo'd tcpdump is unreliable, so explicitly send
    # SIGTERM to the remote tcpdump too.
    try:
        subprocess.call(ssh_cmd(LINUX_HOST, LINUX_USER,
                                "sudo pkill -INT tcpdump"))
    except OSError:
        pass
    try:
        proc.terminate()
    except OSError:
        pass
    try:
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except OSError:
            pass

    # Download.
    argv = [
        "scp", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "{0}:{1}".format(LINUX_HOST, pcap_path),
        local_pcap_path,
    ]
    print("coordinator: scp {0} -> {1}".format(pcap_path, local_pcap_path))
    subprocess.call(argv)
    # Best-effort tidy of the remote pcap so we don't leave artefacts
    # accumulating on debian-nat across runs.
    subprocess.call(ssh_cmd(LINUX_HOST, LINUX_USER,
                            "sudo rm -f {0}".format(pcap_path)))


def probe_host_offset(host, user, python_cmd, label):
    """Query the remote host's `time.time()` and compute its clock
    offset relative to this coordinator's clock.

    Method: record T0 just before SSH, run `python -c "..."` on the
    remote, record T1 just after it returns, parse remote's reported
    time as host_local_time.  Offset = host_local_time - (T0+T1)/2.

    This is the simple "probe-and-offset" approach -- equivalent to
    a one-sample NTP exchange without the round-trip-bias correction.
    Good enough for a single-shot smoke test where the absolute punch
    moment only needs to be aligned to within a few hundred ms.

    Returns a float offset in seconds.  Positive offset means the
    host's clock is AHEAD of the coordinator's.
    """
    remote_cmd = '{0} -c "import time; print(time.time())"'.format(python_cmd)
    argv = ssh_cmd(host, user, remote_cmd)
    print("coordinator: probing clock offset for {0} ({1})".format(label, host))
    coordinator_t0 = time.time()
    try:
        out = subprocess.check_output(argv, stderr=subprocess.STDOUT,
                                      universal_newlines=True)
    except subprocess.CalledProcessError as exc:
        print("coordinator: probe failed for {0}: rc={1} out={2!r}".format(
            label, exc.returncode, exc.output))
        raise
    coordinator_t1 = time.time()

    # The remote may emit Windows-style line endings or extra noise
    # before the float (e.g. cmd.exe banner if any).  Take the last
    # non-blank line and parse it.
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if not lines:
        raise RuntimeError(
            "empty time probe output for {0}: {1!r}".format(label, out))
    try:
        host_local_time = float(lines[-1])
    except ValueError:
        raise RuntimeError(
            "could not parse time from {0}: {1!r}".format(label, out))

    midpoint = (coordinator_t0 + coordinator_t1) / 2.0
    rtt = coordinator_t1 - coordinator_t0
    offset = host_local_time - midpoint
    print(("coordinator: {0} clock probe: coord_t0={1:.3f} coord_t1={2:.3f} "
           "midpoint={3:.3f} host_t={4:.3f} rtt={5:.3f}s offset={6:.3f}s").format(
        label, coordinator_t0, coordinator_t1, midpoint,
        host_local_time, rtt, offset))
    return offset


def build_xp_argv(xp_dest, punch_at):
    """Compose the cmd.exe one-liner that launches the responder.

    We need PYTHONPATH set so the in-repo aionetiface checkout is
    used (pip install -e .. on XP can lag the repo state).
    """
    py = XP_PYTHON
    src1 = XP_REPO_P2PD + r"\src"
    src2 = XP_REPO_AIONETIFACE + r"\src"
    # cmd.exe quoting: outer ssh wraps the whole thing in shell
    # quoting on the local side, so the remote sees a single arg.
    remote_cmd = (
        'set PYTHONPATH={0};{1} && '
        '"{2}" "{3}" '
        '--local-ip {4} --local-port {5} '
        '--peer-public-ip {6} --peer-port {7} '
        '--punch-at {8} '
        '--iface-pcap-name {9}'
    ).format(
        src1, src2, py, xp_dest,
        XP_LAN_IP, XP_PORT,
        LINUX_PUBLIC_IP, LINUX_PORT,
        repr(punch_at),  # ensures full precision in the string form
        XP_PCAP_IFACE,
    )
    return ssh_cmd(XP_HOST, XP_USER, remote_cmd)


def build_linux_argv(linux_dest, punch_at):
    remote_cmd = (
        "{0} {1} "
        "--local-ip {2} --local-port {3} "
        "--peer-public-ip {4} --peer-port {5} "
        "--punch-at {6}"
    ).format(
        LINUX_PYTHON, linux_dest,
        LINUX_LAN_IP, LINUX_PORT,
        XP_PUBLIC_IP, XP_PORT,
        repr(punch_at),
    )
    return ssh_cmd(LINUX_HOST, LINUX_USER, remote_cmd)


def main():
    args = parse_args()
    artefact_dir = ensure_artefact_dir(args.artefact_dir)

    xp_log = os.path.join(artefact_dir, "xp_responder.out")
    linux_log = os.path.join(artefact_dir, "linux_connector.out")
    remote_pcap = "/tmp/cross_nat_pcap_smoke.pcap"
    local_pcap = os.path.join(artefact_dir, "cross_nat_pcap_smoke.pcap")

    print("coordinator: artefact dir = {0}".format(artefact_dir))
    print("coordinator: predicted ports linux={0} xp={1}".format(
        LINUX_PORT, XP_PORT))

    try:
        xp_dest, linux_dest = upload_scripts()
    except RuntimeError as exc:
        print("coordinator: upload_scripts failed: {0}".format(exc))
        return 2

    # Probe each host's clock BEFORE starting tcpdump or workers, so
    # we know the offset between the coordinator's clock and each
    # worker's clock.  XP's BIOS clock in particular can be hours off
    # (observed: ~11h ahead on previous run) and a naive shared
    # absolute punch_at fires immediately on XP while Linux sleeps
    # for minutes.  See p2pd CLAUDE.md / previous diagnosis.
    try:
        linux_offset = probe_host_offset(
            LINUX_HOST, LINUX_USER, LINUX_PYTHON, "linux")
    except Exception as exc:
        print("coordinator: linux clock probe failed: {0}".format(exc))
        return 2
    # XP needs the full path to python.exe.  No outer quoting -- the
    # path has no spaces and cmd.exe parses the `-c "..."` arg
    # correctly only when the leading exe token is unquoted.
    try:
        xp_offset = probe_host_offset(
            XP_HOST, XP_USER, XP_PYTHON, "xp")
    except Exception as exc:
        print("coordinator: xp clock probe failed: {0}".format(exc))
        return 2

    tcpdump_proc = start_tcpdump(remote_pcap)

    # Wall-clock punch time, on the COORDINATOR's clock.  Each
    # worker then receives an absolute timestamp expressed in its
    # OWN local clock by adding that host's offset.
    coordinator_punch_at = time.time() + args.punch_offset
    linux_punch_at = coordinator_punch_at + linux_offset
    xp_punch_at = coordinator_punch_at + xp_offset
    print("coordinator: coordinator_punch_at = {0:.3f} (now+{1:.1f}s)".format(
        coordinator_punch_at, args.punch_offset))
    print("coordinator: linux_offset  = {0:+.3f}s  -> linux_punch_at  = {1:.3f}".format(
        linux_offset, linux_punch_at))
    print("coordinator: xp_offset     = {0:+.3f}s  -> xp_punch_at     = {1:.3f}".format(
        xp_offset, xp_punch_at))

    xp_argv = build_xp_argv(xp_dest, xp_punch_at)
    linux_argv = build_linux_argv(linux_dest, linux_punch_at)

    results = {"xp": None, "linux": None}

    def run_xp():
        results["xp"] = run_remote("xp", xp_argv, xp_log)

    def run_linux():
        results["linux"] = run_remote("linux", linux_argv, linux_log)

    threads = [
        threading.Thread(target=run_xp),
        threading.Thread(target=run_linux),
    ]
    for t in threads:
        t.start()

    # Cap the run.  If either side hangs, we let the deadline
    # expire and report what we got.
    deadline = time.time() + WORKER_TIMEOUT_S + args.punch_offset
    for t in threads:
        remaining = deadline - time.time()
        if remaining <= 0:
            remaining = 1.0
        t.join(timeout=remaining)
    for t in threads:
        if t.is_alive():
            print("coordinator: worker thread still alive past deadline")

    stop_tcpdump(tcpdump_proc, remote_pcap, local_pcap)

    print("coordinator: results xp={0} linux={1}".format(
        results["xp"], results["linux"]))
    print("coordinator: artefacts -> {0}".format(artefact_dir))

    if results["xp"] == 0 and results["linux"] == 0:
        print("coordinator: SMOKE TEST OK")
        return 0
    print("coordinator: SMOKE TEST FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
