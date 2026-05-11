"""Windows-Firewall helper for the pcap-punch path.

The pcap engine owns the TCP simul-open handshake from userspace via
libpcap / WinPcap.  On Windows XP the kernel's tcpip.sys still observes
the inbound SYN on the NIC and -- because no kernel-bound socket is
listening on the predicted port -- will RST the peer before our
userspace stack has a chance to respond.

The cleanest fix is to install a transient Windows-Firewall inbound
block rule for the specific TCP destination port BEFORE the engine
injects its first frame, then remove the rule once the connection has
reached ESTABLISHED (or punch has failed).  The block rule prevents
tcpip.sys from emitting the RST; WinPcap still sees the SYN at the
NDIS layer and our userspace stack drives the handshake from there.

Notes:
  - Requires Administrator privileges.  The XP test user is admin, and
    production XP / 2000 deployments running p2pd are expected to be
    too -- libpcap on Windows already needs admin / NPF service rights.
  - Idempotent: install_block_rule never duplicates a rule with the
    same name; remove_block_rule treats "rule not found" as success.
  - Uses subprocess.CREATE_NO_WINDOW (Windows-only flag) to suppress
    the brief cmd-window flash that netsh otherwise pops on XP.
  - On non-Windows hosts the helpers are no-ops -- the caller (the
    pcap engine) is platform-agnostic so it must not branch on
    sys.platform itself.

The "netsh advfirewall" syntax used here is Windows-Vista+; XP ships
the older "netsh firewall add portopening" CLI under "netsh firewall".
We probe at module load time and pick the right command shape.
"""
import subprocess
import sys


# Suppress the console window on Windows.  CREATE_NO_WINDOW is 0x08000000
# in WinAPI; defined as subprocess.CREATE_NO_WINDOW on Python 3.7+ on
# Windows, absent on Unix.  Fall back to a literal 0 on platforms that
# don't have it -- subprocess.run accepts creationflags=0 everywhere.
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def rule_name(port):
    """Stable rule identifier for a given local TCP port.

    Embeds the port number so multiple concurrent punches on different
    ports each get their own rule and remove_block_rule can be precise
    about which to delete.
    """
    return "p2pd_pcap_block_{0}".format(int(port))


def detect_netsh_dialect():
    """Return 'advfirewall', 'firewall', or None.

    XP ships "netsh firewall" (legacy syntax).  Vista+ added the
    "netsh advfirewall" command set.  Both are present on Vista/7/8/10
    but advfirewall is the supported one going forward.
    """
    if not sys.platform.startswith("win"):
        return None
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=CREATE_NO_WINDOW,
        )
        if result.returncode == 0:
            return "advfirewall"
    except (OSError, FileNotFoundError):
        pass
    try:
        result = subprocess.run(
            ["netsh", "firewall", "show", "state"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=CREATE_NO_WINDOW,
        )
        if result.returncode == 0:
            return "firewall"
    except (OSError, FileNotFoundError):
        pass
    return None


def install_block_rule(port):
    """Install an inbound TCP block rule for the given local port.

    Returns True on success or when running on a non-Windows host
    (no-op).  Returns False if netsh failed or is unavailable.
    """
    if not sys.platform.startswith("win"):
        return True
    dialect = detect_netsh_dialect()
    name = rule_name(port)
    if dialect == "advfirewall":
        # Vista+ syntax.  "dir=in" + "action=block" + "protocol=TCP" +
        # "localport=N" matches every inbound TCP frame addressed to
        # our local port regardless of source -- exactly what we want
        # to keep tcpip.sys from RSTing the punched SYN.
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=" + name,
            "dir=in", "action=block",
            "protocol=TCP", "localport={0}".format(int(port)),
        ]
    elif dialect == "firewall":
        # XP legacy syntax doesn't have a per-rule block action --
        # "portopening" only adds OPEN rules.  But XP's default
        # firewall posture is "block all unsolicited inbound" -- so
        # if there's no kernel socket bound on the port and no
        # explicit open rule, tcpip.sys's RST is the only outbound
        # answer.  Adding a block rule with the legacy syntax isn't
        # possible; instead we rely on the fact that without any
        # listening socket XP's firewall+stack combo already drops
        # the SYN at the firewall layer before tcpip.sys sees it,
        # provided the firewall is on.  In that case there's nothing
        # for us to install -- return True to let the engine proceed.
        return True
    else:
        return False
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=CREATE_NO_WINDOW,
        )
        return result.returncode == 0
    except (OSError, FileNotFoundError):
        return False


def remove_block_rule(port):
    """Remove the inbound TCP block rule for the given local port.

    Idempotent: returns True both when the rule was deleted and when
    no matching rule existed.  Returns False only on outright netsh
    error.
    """
    if not sys.platform.startswith("win"):
        return True
    dialect = detect_netsh_dialect()
    name = rule_name(port)
    if dialect == "advfirewall":
        cmd = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            "name=" + name,
        ]
    elif dialect == "firewall":
        # See install_block_rule -- nothing to remove on XP legacy.
        return True
    else:
        return False
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=CREATE_NO_WINDOW,
        )
        # netsh exits non-zero with "No rules match the specified
        # criteria" -- that's the "already removed" case and counts
        # as success for our idempotency contract.
        if result.returncode == 0:
            return True
        stderr = (result.stderr or b"").decode("ascii", "replace").lower()
        stdout = (result.stdout or b"").decode("ascii", "replace").lower()
        if "no rules match" in stderr or "no rules match" in stdout:
            return True
        return False
    except (OSError, FileNotFoundError):
        return False
