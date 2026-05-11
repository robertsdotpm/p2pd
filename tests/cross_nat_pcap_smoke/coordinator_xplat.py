"""Cross-platform coordinator for the cross-NAT pcap smoke test.

Generalisation of coordinator.py.  Drives the test against any of:
    fedora      Linux x@10.0.1.224
    macos       macOS xx@10.0.1.113
    freebsd     FreeBSD root@10.0.1.225
    ghostbsd    GhostBSD x@10.0.1.152

Connector side is always p2pd.net (debian@p2pd.net), kernel-TCP
tcp_punch via linux_connector.py.  Same clock-offset probe as the XP
coordinator; same per-host punch_at_local; same artefact layout.

Usage:
    python coordinator_xplat.py --responder fedora
    python coordinator_xplat.py --responder macos
    python coordinator_xplat.py --responder freebsd
    python coordinator_xplat.py --responder ghostbsd
"""
import argparse
import os
import subprocess
import sys
import threading
import time


# Connector (kernel-TCP side) -- same as in the XP coordinator.
LINUX_HOST = "p2pd.net"
LINUX_USER = "debian"
LINUX_REPO_P2PD = "/tmp/sweep_repos/p2pd"
LINUX_REPO_AIONETIFACE = "/tmp/sweep_repos/aionetiface"
LINUX_PYTHON = "python3"
LINUX_LAN_IP = "158.69.27.176"
LINUX_PUBLIC_IP = "158.69.27.176"
LINUX_PCAP_IFACE = "eno1"  # for tcpdump on p2pd.net

# Responder host catalogue.  Each entry:
#   host          SSH target (IP)
#   user          SSH user
#   python        python interpreter path
#   repo_base     dir containing the four repos
#   iface         pcap interface name
#   local_ip      NIC IP on LAN side
#   public_ip     IP the peer will see post-NAT
#   dest_path     where on the remote to scp pcap_responder.py + host_firewall.py
RESPONDERS = {
    "fedora": {
        "host": "10.0.1.224",
        "user": "x",
        "python": "/usr/bin/python3.12",
        "repo_p2pd": "/home/x/projects/p2pd",
        "repo_aionetiface": "/home/x/projects/aionetiface",
        "iface": "ens192",
        "local_ip": "10.0.1.224",
        "public_ip": "113.29.240.148",
        "dest_dir": "/tmp",
        # SSH user is not root -- need sudo for pcap_open_live and
        # for the iptables firewall rule install/remove.
        "sudo_prefix": "sudo",
    },
    "macos": {
        "host": "10.0.1.113",
        "user": "xx",
        "python": "/usr/bin/python3",
        "repo_p2pd": "/Users/xx/projects/p2pd",
        "repo_aionetiface": "/Users/xx/projects/aionetiface",
        "iface": "en0",
        "local_ip": "10.0.1.113",
        "public_ip": "113.29.240.148",
        "dest_dir": "/tmp",
        "sudo_prefix": "sudo",
    },
    "freebsd": {
        "host": "10.0.1.225",
        "user": "root",
        "python": "python3",
        "repo_p2pd": "/root/projects/p2pd",
        "repo_aionetiface": "/root/projects/aionetiface",
        "iface": "em0",
        "local_ip": "10.0.1.225",
        "public_ip": "113.29.240.148",
        "dest_dir": "/tmp",
        # SSH user is root -- pf manipulation and pcap don't need
        # sudo (which isn't installed on this VM anyway).
        "sudo_prefix": "",
    },
    "ghostbsd": {
        "host": "10.0.1.152",
        "user": "x",
        "python": "python3",
        "repo_p2pd": "/home/x/projects/p2pd",
        "repo_aionetiface": "/home/x/projects/aionetiface",
        # ghostbsd memory: vmx1 is the LAN dual-stack NIC.
        "iface": "vmx1",
        "local_ip": "10.0.1.152",
        "public_ip": "113.29.240.148",
        "dest_dir": "/tmp",
        "sudo_prefix": "sudo",
    },
}


LINUX_PORT = 43201
RESPONDER_PORT = 43202

PUNCH_OFFSET_S = 15.0
WORKER_TIMEOUT_S = 90.0
ARTEFACT_DIR_BASE = "/tmp/cross_nat_pcap_smoke"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--responder", required=True,
                        choices=sorted(RESPONDERS.keys()))
    parser.add_argument("--artefact-dir", default=None)
    parser.add_argument("--punch-offset", default=PUNCH_OFFSET_S, type=float)
    parser.add_argument("--skip-firewall", action="store_true")
    return parser.parse_args()


def ensure_artefact_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)
    return path


def ssh_cmd(host, user, remote_cmd, port=None):
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


def scp_to_remote(local_path, host, user, dest_path):
    target = "{0}@{1}:{2}".format(user, host, dest_path) if user else \
        "{0}:{1}".format(host, dest_path)
    argv = [
        "scp", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        local_path, target,
    ]
    print("coordinator: scp {0} -> {1}@{2}:{3}".format(
        os.path.basename(local_path), user, host, dest_path))
    rc = subprocess.call(argv)
    if rc != 0:
        raise RuntimeError(
            "scp {0} -> {1}@{2} failed rc={3}".format(
                local_path, user, host, rc))


def run_remote(name, argv, output_path):
    print("coordinator: launching {0}: {1}".format(
        name, " ".join(argv[:3] + ["..."])))
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        bufsize=1, universal_newlines=True,
    )
    with open(output_path, "w") as out:
        for line in proc.stdout:
            sys.stdout.write("[{0}] {1}".format(name, line))
            sys.stdout.flush()
            out.write(line)
    rc = proc.wait()
    print("coordinator: {0} exited with rc={1}".format(name, rc))
    return rc


def upload_scripts(responder_cfg):
    here = os.path.dirname(os.path.abspath(__file__))
    pcap_script = os.path.join(here, "pcap_responder.py")
    fw_script = os.path.join(here, "host_firewall.py")
    linux_script = os.path.join(here, "linux_connector.py")

    dest_dir = responder_cfg["dest_dir"]
    pcap_dest = dest_dir + "/pcap_responder.py"
    fw_dest = dest_dir + "/host_firewall.py"
    scp_to_remote(pcap_script,
                  responder_cfg["host"], responder_cfg["user"], pcap_dest)
    scp_to_remote(fw_script,
                  responder_cfg["host"], responder_cfg["user"], fw_dest)

    # Linux connector to p2pd.net.
    linux_dest = "/tmp/linux_connector.py"
    scp_to_remote(linux_script, LINUX_HOST, LINUX_USER, linux_dest)
    return pcap_dest, linux_dest


def start_tcpdump(pcap_path):
    bpf = "tcp and (port {0} or port {1})".format(LINUX_PORT, RESPONDER_PORT)
    remote_cmd = (
        "sudo tcpdump -i {0} -w {1} '{2}' 2>&1"
    ).format(LINUX_PCAP_IFACE, pcap_path, bpf)
    argv = ssh_cmd(LINUX_HOST, LINUX_USER, remote_cmd)
    print("coordinator: starting remote tcpdump on {0} -> {1}".format(
        LINUX_PCAP_IFACE, pcap_path))
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        bufsize=1, universal_newlines=True,
    )
    time.sleep(2.0)
    return proc


def stop_tcpdump(proc, pcap_path, local_pcap_path):
    print("coordinator: stopping remote tcpdump")
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

    pcap_src = "{0}@{1}:{2}".format(LINUX_USER, LINUX_HOST, pcap_path)
    argv = [
        "scp", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        pcap_src, local_pcap_path,
    ]
    print("coordinator: scp {0} -> {1}".format(pcap_path, local_pcap_path))
    subprocess.call(argv)
    subprocess.call(ssh_cmd(LINUX_HOST, LINUX_USER,
                            "sudo rm -f {0}".format(pcap_path)))


def probe_host_offset(host, user, python_cmd, label):
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


def build_responder_argv(responder_cfg, pcap_dest, punch_at, skip_firewall):
    py = responder_cfg["python"]
    src1 = responder_cfg["repo_p2pd"] + "/src"
    src2 = responder_cfg["repo_aionetiface"] + "/src"
    extra = " --skip-firewall" if skip_firewall else ""
    # pcap_open_live requires root on Linux/macOS/BSD.  We invoke the
    # responder under the host's `sudo_prefix` -- "sudo" on hosts
    # where the SSH user is not root, "" on hosts where the SSH user
    # is root (e.g. FreeBSD where sudo isn't installed by default).
    # The `sudo PYTHONPATH=... <python> ...` form propagates the
    # PYTHONPATH env var through sudo's env_keep filter (RHEL/Fedora
    # strip PYTHONPATH by default; explicit assignment slips past).
    sudo_prefix = responder_cfg.get("sudo_prefix", "sudo")
    if sudo_prefix:
        env_part = "{0} PYTHONPATH={1}:{2}".format(
            sudo_prefix, src1, src2)
    else:
        env_part = "PYTHONPATH={0}:{1}".format(src1, src2)
    remote_cmd = (
        "{0} {1} {2} "
        "--iface {3} "
        "--local-ip {4} --local-port {5} "
        "--remote-ip {6} --remote-port {7} "
        "--punch-at {8}{9}"
    ).format(
        env_part, py, pcap_dest,
        responder_cfg["iface"],
        responder_cfg["local_ip"], RESPONDER_PORT,
        LINUX_PUBLIC_IP, LINUX_PORT,
        repr(punch_at), extra,
    )
    return ssh_cmd(responder_cfg["host"], responder_cfg["user"], remote_cmd)


def build_linux_argv(linux_dest, responder_cfg, punch_at):
    remote_cmd = (
        "{0} {1} "
        "--local-ip {2} --local-port {3} "
        "--peer-public-ip {4} --peer-port {5} "
        "--punch-at {6}"
    ).format(
        LINUX_PYTHON, linux_dest,
        LINUX_LAN_IP, LINUX_PORT,
        responder_cfg["public_ip"], RESPONDER_PORT,
        repr(punch_at),
    )
    return ssh_cmd(LINUX_HOST, LINUX_USER, remote_cmd)


def main():
    args = parse_args()
    responder_cfg = RESPONDERS[args.responder]

    artefact_dir = args.artefact_dir or os.path.join(
        ARTEFACT_DIR_BASE, args.responder)
    ensure_artefact_dir(artefact_dir)

    responder_log = os.path.join(artefact_dir, "pcap_responder.out")
    linux_log = os.path.join(artefact_dir, "linux_connector.out")
    remote_pcap = "/tmp/cross_nat_pcap_smoke.{0}.pcap".format(args.responder)
    local_pcap = os.path.join(
        artefact_dir, "cross_nat_pcap_smoke.{0}.pcap".format(args.responder))

    print("coordinator: responder = {0} ({1}@{2})".format(
        args.responder, responder_cfg["user"], responder_cfg["host"]))
    print("coordinator: artefact dir = {0}".format(artefact_dir))
    print("coordinator: predicted ports linux={0} responder={1}".format(
        LINUX_PORT, RESPONDER_PORT))

    try:
        pcap_dest, linux_dest = upload_scripts(responder_cfg)
    except RuntimeError as exc:
        print("coordinator: upload_scripts failed: {0}".format(exc))
        return 2

    try:
        linux_offset = probe_host_offset(
            LINUX_HOST, LINUX_USER, LINUX_PYTHON, "linux")
    except Exception as exc:
        print("coordinator: linux clock probe failed: {0}".format(exc))
        return 2
    try:
        responder_offset = probe_host_offset(
            responder_cfg["host"], responder_cfg["user"],
            responder_cfg["python"], args.responder)
    except Exception as exc:
        print("coordinator: {0} clock probe failed: {1}".format(
            args.responder, exc))
        return 2

    tcpdump_proc = start_tcpdump(remote_pcap)

    coordinator_punch_at = time.time() + args.punch_offset
    linux_punch_at = coordinator_punch_at + linux_offset
    responder_punch_at = coordinator_punch_at + responder_offset
    print("coordinator: coordinator_punch_at = {0:.3f} (now+{1:.1f}s)".format(
        coordinator_punch_at, args.punch_offset))
    print("coordinator: linux_offset      = {0:+.3f}s  -> linux_punch_at      = {1:.3f}".format(
        linux_offset, linux_punch_at))
    print("coordinator: {0}_offset = {1:+.3f}s  -> responder_punch_at = {2:.3f}".format(
        args.responder, responder_offset, responder_punch_at))

    responder_argv = build_responder_argv(
        responder_cfg, pcap_dest, responder_punch_at, args.skip_firewall)
    linux_argv = build_linux_argv(linux_dest, responder_cfg, linux_punch_at)

    results = {"responder": None, "linux": None}

    def run_responder():
        results["responder"] = run_remote(
            args.responder, responder_argv, responder_log)

    def run_linux():
        results["linux"] = run_remote("linux", linux_argv, linux_log)

    threads = [
        threading.Thread(target=run_responder),
        threading.Thread(target=run_linux),
    ]
    for t in threads:
        t.start()

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

    print("coordinator: results responder={0} linux={1}".format(
        results["responder"], results["linux"]))
    print("coordinator: artefacts -> {0}".format(artefact_dir))

    if results["responder"] == 0 and results["linux"] == 0:
        print("coordinator: SMOKE TEST OK")
        return 0
    print("coordinator: SMOKE TEST FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
