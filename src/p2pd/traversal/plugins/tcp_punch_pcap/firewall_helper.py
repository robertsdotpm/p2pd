"""Per-OS host-firewall install/remove for the v2 pcap punch.

Reuses the same install/remove pattern as the smoke-test
host_firewall.py module but here it lives inside the plugin so
runtime callers don't need the tests path on sys.path.

Contract:
    install_block_ports(ports) installs an inbound-TCP DROP rule
    covering each port in `ports`. Returns the list of ports that
    were actually installed (so remove_block_ports can target only
    those).

    remove_block_ports(ports) removes whatever install installed.
    Idempotent / best-effort: never raises so callers can use it
    in a finally clause without masking the original exception.

Platforms:
    linux           iptables -I INPUT 1 -p tcp --dport N -j DROP
    darwin / *bsd   pf anchor "p2pd-pcap-v2-block-<port>"
    windows         no-op (XP-listener case uses the dispatcher
                    policy "rely on existing firewall state"
                    documented in the original tcp_punch_pcap/
                    firewall.py).

The dispatcher-policy guard from tcp_punch_pcap/firewall.py
covered the smoke-test orchestration where root-controlled rule
mutations were forbidden mid-run. The v2 plugin runs from inside
the host's own process tree (Node + auto_connect), so the live-
process can manipulate its own firewall as long as it
restores state. Mirror the host_firewall.py try/finally contract.
"""
import os
import subprocess
import sys

try:
    from aionetiface import log
except ImportError:
    def log(msg):
        print(msg)


def is_linux():
    return sys.platform.startswith("linux")


def is_darwin():
    return sys.platform.startswith("darwin")


def is_bsd():
    return (
        sys.platform.startswith("freebsd")
        or sys.platform.startswith("openbsd")
        or sys.platform.startswith("netbsd")
        or sys.platform.startswith("dragonfly")
        or ("bsd" in sys.platform and not sys.platform.startswith("win"))
    )


def is_windows():
    return sys.platform.startswith("win")


def need_sudo():
    """Return True if we should prepend `sudo` (non-root POSIX)."""
    if is_windows():
        return False
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return False
    except OSError:
        return False
    return True


def sudo_argv(argv):
    """Prepend sudo when running unprivileged on POSIX."""
    if need_sudo():
        return ["sudo"] + list(argv)
    return list(argv)


def run_cmd(argv, stdin_data=None, timeout=10):
    """Run a command. Returns (rc, stdout, stderr). Never raises."""
    log("firewall_helper: exec: {0}".format(" ".join(argv)))
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if stdin_data is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        log("firewall_helper: spawn failed: {0}".format(exc))
        return (127, "", str(exc))
    if stdin_data is not None:
        stdin_bytes = stdin_data.encode("ascii")
    else:
        stdin_bytes = None
    try:
        out_b, err_b = proc.communicate(input=stdin_bytes, timeout=timeout)
    except Exception as exc:
        try:
            proc.kill()
        except OSError:
            pass
        log("firewall_helper: communicate failed: {0}".format(exc))
        return (124, "", str(exc))
    out = out_b.decode("utf-8", errors="replace") if out_b else ""
    err = err_b.decode("utf-8", errors="replace") if err_b else ""
    rc = proc.returncode
    log("firewall_helper: rc={0} stdout={1} stderr={2}".format(
        rc, out.strip(), err.strip(),
    ))
    return (rc, out, err)


# --- Linux -----------------------------------------------------------------


def linux_install(port):
    rc, out, err = run_cmd(sudo_argv([
        "iptables", "-I", "INPUT", "1",
        "-p", "tcp", "--dport", str(int(port)),
        "-j", "DROP",
    ]))
    return rc == 0


def linux_remove(port):
    for guard in range(5):
        rc, out, err = run_cmd(sudo_argv([
            "iptables", "-D", "INPUT",
            "-p", "tcp", "--dport", str(int(port)),
            "-j", "DROP",
        ]))
        if rc != 0:
            return
    log("firewall_helper: linux_remove({0}) 5 matches removed".format(port))


# --- pf (macOS + BSD) ------------------------------------------------------


def pf_anchor_name(port):
    return "p2pd-pcap-v2-block-{0}".format(int(port))


def pf_install(port):
    anchor = pf_anchor_name(port)
    rule = "block in proto tcp from any to any port {0}\n".format(int(port))
    run_cmd(sudo_argv(["pfctl", "-e"]))
    rc, out, err = run_cmd(
        sudo_argv(["pfctl", "-a", anchor, "-f", "-"]),
        stdin_data=rule,
    )
    if rc != 0:
        return False
    rc2, current_rules, err2 = run_cmd(sudo_argv(["pfctl", "-sr"]))
    if rc2 != 0:
        current_rules = ""
    hook_line = "anchor \"{0}\"\n".format(anchor)
    combined = current_rules
    if not combined.endswith("\n"):
        combined = combined + "\n"
    combined = combined + hook_line
    rc3, out3, err3 = run_cmd(
        sudo_argv(["pfctl", "-f", "-"]),
        stdin_data=combined,
    )
    if rc3 != 0:
        run_cmd(sudo_argv(["pfctl", "-a", anchor, "-F", "rules"]))
        return False
    return True


def pf_remove(port):
    anchor = pf_anchor_name(port)
    run_cmd(sudo_argv(["pfctl", "-a", anchor, "-F", "rules"]))
    rc, current_rules, err = run_cmd(sudo_argv(["pfctl", "-sr"]))
    if rc != 0 or not current_rules:
        return
    hook_line = "anchor \"{0}\"".format(anchor)
    kept = []
    for raw in current_rules.splitlines():
        if hook_line in raw:
            continue
        kept.append(raw)
    new_rules = "\n".join(kept)
    if new_rules and not new_rules.endswith("\n"):
        new_rules = new_rules + "\n"
    run_cmd(
        sudo_argv(["pfctl", "-f", "-"]),
        stdin_data=new_rules,
    )


# --- Unified -------------------------------------------------------------


def install_block_ports(ports):
    """Install inbound-TCP DROP rules for each port. Returns ports that
    were successfully installed (so the caller's remove pairs match).
    Errors per-port are logged and the offending port is dropped from
    the returned list -- callers should still call remove_block_ports
    with the returned list in a finally clause.
    """
    installed = []
    if is_windows():
        log("firewall_helper: install_block_ports no-op on Windows")
        return installed
    for port in ports:
        try:
            if is_linux():
                ok = linux_install(port)
            elif is_darwin() or is_bsd():
                ok = pf_install(port)
            else:
                log("firewall_helper: unsupported platform {0}".format(
                    sys.platform,
                ))
                return installed
        except Exception as exc:
            log("firewall_helper: install({0}) raised {1}".format(port, exc))
            ok = False
        if ok:
            installed.append(int(port))
        else:
            log("firewall_helper: install({0}) failed".format(port))
    return installed


def remove_block_ports(ports):
    """Remove inbound-TCP DROP rules for each port. Idempotent;
    swallows errors so finally-clauses don't mask real exceptions.
    """
    if is_windows():
        return
    for port in ports:
        try:
            if is_linux():
                linux_remove(port)
            elif is_darwin() or is_bsd():
                pf_remove(port)
        except Exception as exc:
            log("firewall_helper: remove({0}) swallowed {1}".format(port, exc))
