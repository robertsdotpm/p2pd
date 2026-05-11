"""Coordinator: pipe PunchMsg JSON between v2_responder (fedora, pcap)
and legacy_connector (p2pd.net, kernel-TCP tcp_punch plugin).

Each peer's driver prints "SIG:{...json...}" lines to stdout on
outbound; we forward them to the other peer's stdin. Non-SIG
output lines are logged with a peer prefix.

Constraint: stdin-to-SSH is fiddly because OpenSSH closes the
remote stdin half when the SSH connection's local stdin closes.
We open SSH with stdin piped from us and never close it until both
peers are done.

CLI:
    python coordinator_v2_legacy.py --artefact-dir DIR --punch-offset 15
"""
import argparse
import json
import os
import subprocess
import sys
import threading
import time
import uuid


# Match coordinator_xplat.py.
FEDORA_HOST = "10.0.1.224"
FEDORA_USER = "x"
FEDORA_PYTHON = "/usr/bin/python3.12"
FEDORA_IFACE = "ens192"
FEDORA_LOCAL_IP = "10.0.1.224"
FEDORA_PUBLIC_IP = "113.29.240.148"
FEDORA_DEST_DIR = "/tmp"
FEDORA_REPO_P2PD = "/home/x/projects/p2pd"
FEDORA_REPO_AIONETIFACE = "/home/x/projects/aionetiface"
FEDORA_REPO_SIDEWIRE = "/home/x/projects/sidewire"
FEDORA_REPO_NAMEBUMP = "/home/x/projects/namebump"

LINUX_HOST = "p2pd.net"
LINUX_USER = "debian"
LINUX_PYTHON = "python3"
LINUX_IFACE = "eno1"
LINUX_LOCAL_IP = "158.69.27.176"
LINUX_PUBLIC_IP = "158.69.27.176"
LINUX_DEST_DIR = "/tmp"
LINUX_REPO_P2PD = "/tmp/sweep_repos/p2pd"
LINUX_REPO_AIONETIFACE = "/tmp/sweep_repos/aionetiface"
LINUX_REPO_SIDEWIRE = "/tmp/sweep_repos/sidewire"
LINUX_REPO_NAMEBUMP = "/tmp/sweep_repos/namebump"

ARTEFACT_DIR_BASE = "/tmp/cross_nat_pcap_smoke_v2_legacy"


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--artefact-dir", default=None)
    p.add_argument("--timeout", default=90.0, type=float)
    p.add_argument("--no-tcpdump", action="store_true")
    return p.parse_args()


def ensure_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)
    return path


def ssh_argv(host, user, remote_cmd):
    # NO -tt: a TTY would line-discipline the stdin/stdout pipes
    # (echo, CRLF translation) and corrupt the SIG: JSON channel.
    return [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=15",
        "{0}@{1}".format(user, host),
        remote_cmd,
    ]


def scp_to(src, host, user, dest):
    target = "{0}@{1}:{2}".format(user, host, dest)
    rc = subprocess.call([
        "scp", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        src, target,
    ])
    if rc != 0:
        raise RuntimeError("scp failed rc={0}".format(rc))


def rsync_to(src_dir, host, user, dest_dir):
    """Rsync a working tree to the remote so unpushed commits ride along."""
    rc = subprocess.call([
        "rsync", "-rltD",  # NOT -a: skip group/owner preservation
        "--exclude=__pycache__",
        "--exclude=*.egg-info",
        "--exclude=build",
        "--exclude=.git",
        "--exclude=.pytest_cache",
        "-e", "ssh -o StrictHostKeyChecking=no "
              "-o UserKnownHostsFile=/dev/null -o ConnectTimeout=15",
        src_dir + "/", "{0}@{1}:{2}/".format(user, host, dest_dir),
    ])
    if rc != 0:
        raise RuntimeError("rsync to {0} failed rc={1}".format(host, rc))


def start_tcpdump(pcap_path):
    bpf = "tcp and host {0}".format(FEDORA_PUBLIC_IP)
    cmd = "sudo tcpdump -i {0} -w {1} '{2}' 2>&1".format(
        LINUX_IFACE, pcap_path, bpf)
    proc = subprocess.Popen(
        ssh_argv(LINUX_HOST, LINUX_USER, cmd),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        bufsize=1, universal_newlines=True,
    )
    time.sleep(2.0)
    return proc


def stop_tcpdump(proc, remote_path, local_path):
    try:
        subprocess.call(ssh_argv(LINUX_HOST, LINUX_USER,
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
    subprocess.call([
        "scp", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "{0}@{1}:{2}".format(LINUX_USER, LINUX_HOST, remote_path),
        local_path,
    ])
    subprocess.call(ssh_argv(LINUX_HOST, LINUX_USER,
                             "sudo rm -f {0}".format(remote_path)))


class PeerProcess(object):
    """Wraps an SSH subprocess that talks to a remote driver script
    via line-oriented JSON SIG: protocol on stdin/stdout."""

    def __init__(self, name, argv, log_path, peer_other_holder, log_lock):
        self.name = name
        self.argv = argv
        self.log_path = log_path
        self.proc = None
        self.peer_other_holder = peer_other_holder
        self.log_lock = log_lock
        self.exit_code = None

    def start(self):
        self.proc = subprocess.Popen(
            self.argv,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1, universal_newlines=True,
        )

    def deliver(self, line):
        """Write a line to this peer's stdin."""
        try:
            self.proc.stdin.write(line)
            self.proc.stdin.flush()
        except Exception as exc:
            with self.log_lock:
                print("coordinator: deliver to {0} failed: {1}".format(
                    self.name, exc), flush=True)

    def reader_loop(self):
        with open(self.log_path, "w") as log:
            for line in self.proc.stdout:
                with self.log_lock:
                    sys.stdout.write("[{0}] {1}".format(self.name, line))
                    sys.stdout.flush()
                log.write(line)
                log.flush()
                if line.startswith("SIG:"):
                    peer_other = self.peer_other_holder[0]
                    if peer_other is not None:
                        peer_other.deliver(line)
        self.exit_code = self.proc.wait()
        with self.log_lock:
            print("coordinator: {0} exited rc={1}".format(
                self.name, self.exit_code), flush=True)


def main():
    args = parse_args()

    artefact_dir = args.artefact_dir or ARTEFACT_DIR_BASE
    ensure_dir(artefact_dir)

    plugin_id = "v2leg-" + uuid.uuid4().hex[:10]
    print("coordinator: plugin_id = {0}".format(plugin_id))
    print("coordinator: artefact_dir = {0}".format(artefact_dir))

    # Sync working trees so peers have the v2 plugin + latest tcp_punch.
    here = os.path.dirname(os.path.abspath(__file__))
    repo_p2pd = os.path.abspath(os.path.join(here, "..", ".."))
    repo_aionet = os.path.abspath(os.path.join(repo_p2pd, "..", "aionetiface"))

    repo_sidewire = os.path.abspath(os.path.join(repo_p2pd, "..", "sidewire"))
    repo_namebump = os.path.abspath(os.path.join(repo_p2pd, "..", "namebump"))

    print("coordinator: rsyncing p2pd -> fedora")
    rsync_to(repo_p2pd, FEDORA_HOST, FEDORA_USER, FEDORA_REPO_P2PD)
    print("coordinator: rsyncing aionetiface -> fedora")
    rsync_to(repo_aionet, FEDORA_HOST, FEDORA_USER, FEDORA_REPO_AIONETIFACE)
    print("coordinator: rsyncing sidewire -> fedora")
    rsync_to(repo_sidewire, FEDORA_HOST, FEDORA_USER, FEDORA_REPO_SIDEWIRE)
    print("coordinator: rsyncing namebump -> fedora")
    rsync_to(repo_namebump, FEDORA_HOST, FEDORA_USER, FEDORA_REPO_NAMEBUMP)
    print("coordinator: rsyncing p2pd -> p2pd.net")
    rsync_to(repo_p2pd, LINUX_HOST, LINUX_USER, LINUX_REPO_P2PD)
    print("coordinator: rsyncing aionetiface -> p2pd.net")
    rsync_to(repo_aionet, LINUX_HOST, LINUX_USER, LINUX_REPO_AIONETIFACE)
    print("coordinator: rsyncing sidewire -> p2pd.net")
    rsync_to(repo_sidewire, LINUX_HOST, LINUX_USER, LINUX_REPO_SIDEWIRE)
    print("coordinator: rsyncing namebump -> p2pd.net")
    rsync_to(repo_namebump, LINUX_HOST, LINUX_USER, LINUX_REPO_NAMEBUMP)

    # Driver scripts already live inside the synced trees at
    # tests/cross_nat_pcap_smoke/.
    fedora_driver = FEDORA_REPO_P2PD + "/tests/cross_nat_pcap_smoke/v2_responder.py"
    linux_driver = LINUX_REPO_P2PD + "/tests/cross_nat_pcap_smoke/legacy_connector.py"

    # Build the remote invocations.
    fedora_pp = "{0}/src:{1}/src:{2}/src:{3}/src".format(
        FEDORA_REPO_P2PD, FEDORA_REPO_AIONETIFACE,
        FEDORA_REPO_SIDEWIRE, FEDORA_REPO_NAMEBUMP)
    fedora_cmd = (
        "sudo PYTHONPATH={0} {1} {2} "
        "--iface {3} --local-ip {4} "
        "--remote-ip {5} --remote-public-ip {5} "
        "--plugin-id {6} --timeout {7}"
    ).format(
        fedora_pp, FEDORA_PYTHON, fedora_driver,
        FEDORA_IFACE, FEDORA_LOCAL_IP,
        LINUX_PUBLIC_IP,
        plugin_id, int(args.timeout),
    )

    linux_pp = "{0}/src:{1}/src:{2}/src:{3}/src".format(
        LINUX_REPO_P2PD, LINUX_REPO_AIONETIFACE,
        LINUX_REPO_SIDEWIRE, LINUX_REPO_NAMEBUMP)
    linux_cmd = (
        "PYTHONPATH={0} {1} {2} "
        "--iface {3} --local-ip {4} "
        "--remote-ip {5} "
        "--plugin-id {6} --timeout {7}"
    ).format(
        linux_pp, LINUX_PYTHON, linux_driver,
        LINUX_IFACE, LINUX_LOCAL_IP,
        FEDORA_PUBLIC_IP,
        plugin_id, int(args.timeout),
    )

    log_lock = threading.Lock()
    peer_other_holder_v2 = [None]
    peer_other_holder_lg = [None]

    v2 = PeerProcess(
        "v2", ssh_argv(FEDORA_HOST, FEDORA_USER, fedora_cmd),
        os.path.join(artefact_dir, "v2_responder.out"),
        peer_other_holder_v2, log_lock,
    )
    legacy = PeerProcess(
        "legacy", ssh_argv(LINUX_HOST, LINUX_USER, linux_cmd),
        os.path.join(artefact_dir, "legacy_connector.out"),
        peer_other_holder_lg, log_lock,
    )

    peer_other_holder_v2[0] = legacy
    peer_other_holder_lg[0] = v2

    tcpdump_proc = None
    remote_pcap = "/tmp/cross_nat_v2_legacy.pcap"
    local_pcap = os.path.join(artefact_dir, "cross_nat_v2_legacy.pcap")
    if not args.no_tcpdump:
        try:
            tcpdump_proc = start_tcpdump(remote_pcap)
        except Exception as exc:
            print("coordinator: tcpdump start failed: {0}".format(exc))

    v2.start()
    legacy.start()
    print("coordinator: drivers launched")

    t1 = threading.Thread(target=v2.reader_loop)
    t2 = threading.Thread(target=legacy.reader_loop)
    t1.start()
    t2.start()

    deadline = time.time() + args.timeout + 30.0
    while time.time() < deadline and (t1.is_alive() or t2.is_alive()):
        time.sleep(1.0)

    if t1.is_alive() or t2.is_alive():
        print("coordinator: deadline exceeded; killing drivers")
        for p in (v2.proc, legacy.proc):
            try:
                p.kill()
            except Exception:
                pass

    t1.join(timeout=10)
    t2.join(timeout=10)

    if tcpdump_proc is not None:
        stop_tcpdump(tcpdump_proc, remote_pcap, local_pcap)

    print("coordinator: rc v2={0} legacy={1}".format(
        v2.exit_code, legacy.exit_code))
    print("coordinator: artefacts -> {0}".format(artefact_dir))

    # Verify firewall cleanup on fedora.
    print("coordinator: post-run iptables check on fedora")
    subprocess.call(ssh_argv(
        FEDORA_HOST, FEDORA_USER,
        "sudo iptables -L INPUT -n --line-numbers | head -30",
    ))

    if v2.exit_code == 0 and legacy.exit_code == 0:
        print("coordinator: V2<->LEGACY OK")
        return 0
    print("coordinator: V2<->LEGACY FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
