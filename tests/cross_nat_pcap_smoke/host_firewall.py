"""Per-OS host firewall helpers for the cross-NAT pcap smoke test.

Background
----------
The cross-NAT pcap experiment relies on the host's kernel TCP stack
NOT responding to an inbound SYN landing on the predicted port -- if
the kernel sees the SYN before our userspace pcap stack does and
nothing is bound to that port, the kernel emits an RST that races our
SYN-ACK out the door.  On Windows XP we sidestep this by binding a
socket (so the kernel "expects" the SYN), but Linux/macOS/BSD don't
have the same XP simul-open quirk in tcpip.sys -- they instead need
the kernel to be told "drop inbound TCP on this port, full stop" so
the kernel never RSTs.  The pcap stack sees the SYN at NDIS/NDIS-
equivalent level regardless.

This module installs a transient inbound-drop rule per-OS and
guarantees teardown via try/finally in the caller.

Supported OS
------------
- linux           iptables -I INPUT 1 -p tcp --dport N -j DROP
- darwin (macOS)  pf with an anchor named "p2pd-pcap-block-<port>"
- freebsd         same pf approach as macOS (syntax identical)
- openbsd/netbsd  pf approach -- untested
- windows         no-op; the XP test path doesn't use this helper

Hard contract: install/remove are idempotent and the remove MUST
succeed even if install partially failed.  Caller is expected to use
try/finally so a single test never leaves a host with a stranded DROP
rule.
"""
import os
import subprocess
import sys


def sudo_argv(argv):
    """Prepend `sudo` to argv unless we're already root or sudo
    isn't on PATH.  Returns a NEW list."""
    if os.geteuid() == 0:
        return list(argv)
    # Resolve sudo lazily; on FreeBSD vanilla there's no sudo, but
    # such hosts also tend to run the responder as root anyway and
    # this code path isn't hit there.
    return ["sudo"] + list(argv)


def is_linux():
    return sys.platform.startswith("linux")


def is_darwin():
    return sys.platform.startswith("darwin")


def is_bsd():
    # FreeBSD / GhostBSD / OpenBSD / NetBSD / DragonFly.
    return (
        sys.platform.startswith("freebsd")
        or sys.platform.startswith("openbsd")
        or sys.platform.startswith("netbsd")
        or sys.platform.startswith("dragonfly")
        or "bsd" in sys.platform
    )


def is_windows():
    return sys.platform.startswith("win")


def run_cmd(argv, stdin_data=None):
    """Run a command, return (rc, stdout, stderr).  Never raises."""
    sys.stderr.write(
        "host_firewall: exec: {0}\n".format(" ".join(argv)))
    sys.stderr.flush()
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if stdin_data is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        sys.stderr.write(
            "host_firewall: spawn failed: {0}\n".format(exc))
        sys.stderr.flush()
        return (127, "", str(exc))
    if stdin_data is not None:
        stdin_bytes = stdin_data.encode("ascii")
    else:
        stdin_bytes = None
    try:
        out_b, err_b = proc.communicate(input=stdin_bytes, timeout=10)
    except Exception as exc:
        try:
            proc.kill()
        except OSError:
            pass
        sys.stderr.write(
            "host_firewall: communicate failed: {0}\n".format(exc))
        sys.stderr.flush()
        return (124, "", str(exc))
    out = out_b.decode("utf-8", errors="replace") if out_b else ""
    err = err_b.decode("utf-8", errors="replace") if err_b else ""
    rc = proc.returncode
    sys.stderr.write(
        "host_firewall: rc={0} stdout={1!r} stderr={2!r}\n".format(
            rc, out.strip(), err.strip()))
    sys.stderr.flush()
    return (rc, out, err)


# --- Linux (iptables) ------------------------------------------------------


def linux_install_block(port):
    rc, out, err = run_cmd(sudo_argv([
        "iptables", "-I", "INPUT", "1",
        "-p", "tcp", "--dport", str(int(port)),
        "-j", "DROP",
    ]))
    if rc != 0:
        raise RuntimeError(
            "iptables install failed rc={0} err={1}".format(rc, err))


def linux_remove_block(port):
    # -D removes the first matching rule.  We may have installed it
    # multiple times across re-runs in pathological cases; loop until
    # the rule is gone.  Cap loop iterations to avoid runaway in
    # the truly unexpected case.
    for guard in range(5):
        rc, out, err = run_cmd(sudo_argv([
            "iptables", "-D", "INPUT",
            "-p", "tcp", "--dport", str(int(port)),
            "-j", "DROP",
        ]))
        if rc != 0:
            # "iptables: Bad rule (does a matching rule exist...)"
            # is the expected exit when no more matches remain.
            return
    sys.stderr.write(
        "host_firewall: linux_remove_block: 5 matches removed, stopping\n")
    sys.stderr.flush()


# --- pf (macOS + BSDs) -----------------------------------------------------


def pf_anchor_name(port):
    # pfctl anchors don't allow long identifiers on some BSDs; keep it
    # short and per-port.
    return "p2pd-pcap-block-{0}".format(int(port))


def pf_install_block(port):
    anchor = pf_anchor_name(port)
    # On macOS, the main pf.conf must include this anchor for it to be
    # loaded into the rule tree.  Modern macOS ships a stock pf.conf
    # that doesn't reference our anchor, so we load it as a
    # standalone ruleset which pfctl evaluates as an isolated anchor
    # but only if pf is enabled AND the anchor is hooked in.
    #
    # The simplest robust approach on every pf flavour is to use the
    # main ruleset (no anchor): write a one-line rule that's globally
    # active for the duration of the test, then flush it.  This avoids
    # the macOS anchor-hooking complication entirely.
    #
    # But "globally active" is dangerous if anything else is using pf.
    # Strategy: prefer the anchor approach when we can verify it's
    # wired into the main ruleset, otherwise fall back to a
    # named-anchor load that we ALSO hook in via a temporary main
    # ruleset edit.  For this smoke test we use the anchor approach
    # only -- the user's hosts have no other pf rules to disrupt and
    # cleanup is trivial.

    rule = "block in proto tcp from any to any port {0}\n".format(
        int(port))

    # Ensure pf is enabled (idempotent; -e returns 1 if already enabled
    # on some BSDs, which is not an error for our purposes).
    run_cmd(sudo_argv(["pfctl", "-e"]))

    # Load the rule into the anchor.
    rc, out, err = run_cmd(
        sudo_argv(["pfctl", "-a", anchor, "-f", "-"]),
        stdin_data=rule,
    )
    if rc != 0:
        raise RuntimeError(
            "pfctl anchor load failed rc={0} err={1}".format(rc, err))

    # Hook the anchor into the main ruleset so it's actually evaluated.
    # On macOS, the stock /etc/pf.conf does NOT include our anchor, so
    # rules loaded into it sit dormant.  We add a one-line main-ruleset
    # rule that references the anchor.  Cleanup must remove this too.
    #
    # CAUTION: `pfctl -f -` on the main ruleset REPLACES the current
    # ruleset entirely.  To avoid wiping any pre-existing rules, we
    # capture the current main ruleset, append our anchor hook, load
    # the combined ruleset, and remember the snapshot for restore.
    rc, current_rules, err = run_cmd(sudo_argv(["pfctl", "-sr"]))
    if rc != 0:
        current_rules = ""

    hook_line = "anchor \"{0}\"\n".format(anchor)
    combined = current_rules
    if not combined.endswith("\n"):
        combined = combined + "\n"
    combined = combined + hook_line

    rc, out, err = run_cmd(
        sudo_argv(["pfctl", "-f", "-"]),
        stdin_data=combined,
    )
    if rc != 0:
        # Anchor was loaded but hook failed; rule still inert.  Flush
        # the anchor so we don't leave artefact behind, then raise.
        run_cmd(sudo_argv(["pfctl", "-a", anchor, "-F", "rules"]))
        raise RuntimeError(
            "pfctl main hook failed rc={0} err={1}".format(rc, err))


def pf_remove_block(port):
    anchor = pf_anchor_name(port)
    # Flush the anchor first (idempotent).
    run_cmd(sudo_argv(["pfctl", "-a", anchor, "-F", "rules"]))
    # Reload the main ruleset WITHOUT our anchor hook.  We grab
    # current rules, strip the hook line, reload.
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


# --- Unified front door ----------------------------------------------------


def install_block(port):
    """Install an inbound-TCP DROP rule for `port` on the current OS.

    Raises RuntimeError on failure.  Caller MUST pair with
    remove_block(port) in a finally clause.
    """
    sys.stderr.write(
        "host_firewall: install_block port={0} platform={1}\n".format(
            port, sys.platform))
    sys.stderr.flush()
    if is_linux():
        return linux_install_block(port)
    if is_darwin() or is_bsd():
        return pf_install_block(port)
    if is_windows():
        sys.stderr.write(
            "host_firewall: windows path is no-op (XP test handles fw separately)\n")
        sys.stderr.flush()
        return
    raise RuntimeError(
        "host_firewall: unsupported platform {0}".format(sys.platform))


def remove_block(port):
    """Remove the inbound-TCP DROP rule for `port` if present.

    Idempotent.  Swallows errors so this can be called from finally
    blocks without masking the original exception.
    """
    sys.stderr.write(
        "host_firewall: remove_block port={0} platform={1}\n".format(
            port, sys.platform))
    sys.stderr.flush()
    try:
        if is_linux():
            linux_remove_block(port)
            return
        if is_darwin() or is_bsd():
            pf_remove_block(port)
            return
        if is_windows():
            return
    except Exception as exc:
        sys.stderr.write(
            "host_firewall: remove_block swallowed {0}\n".format(exc))
        sys.stderr.flush()
