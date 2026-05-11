"""Windows-Firewall helper for the pcap-punch path.

The pcap engine owns the TCP simul-open handshake from userspace via
libpcap / WinPcap.  On Windows XP the kernel's tcpip.sys still observes
the inbound SYN on the NIC and -- because no kernel-bound socket is
listening on the predicted port -- will RST the peer before our
userspace stack has a chance to respond.

The original design installed a transient Windows-Firewall inbound
block rule for the specific TCP destination port BEFORE the engine
injects its first frame, then removed the rule once the connection
reached ESTABLISHED (or punch had failed).  That rule kept tcpip.sys
from emitting the RST while WinPcap still observed the SYN at the
NDIS layer.

DISPATCHER POLICY (2026-05): the smoke-test dispatcher forbids host
firewall mutation.  Both install_block_rule and remove_block_rule are
now no-ops that emit a single warn log line and return True.  The
detect_netsh_dialect probe is preserved because it issues only
"netsh ... show" subcommands (read-only).  Callers must rely on the
existing host firewall configuration to either allow the punched port
through (kernel never replies, so no RST) or to apply some other
non-mutating workaround.  Removing these functions outright would
break the engine import chain; neutering keeps the contract intact.
"""
import subprocess
import sys

try:
    from aionetiface import log
except ImportError:
    def log(msg):
        print(msg)


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
    """No-op: firewall mutation disabled by dispatcher policy.

    Historically installed an inbound TCP block rule on the given
    local port via netsh.  The smoke-test dispatcher now forbids any
    host firewall mutation, so this function only emits a warn log
    and returns True so the caller's contract is preserved.
    """
    log(
        "tcp_punch_pcap.firewall.install_block_rule({0}): "
        "firewall mutation disabled by dispatcher policy; "
        "relying on existing host firewall state.".format(int(port))
    )
    return True


def remove_block_rule(port):
    """No-op: firewall mutation disabled by dispatcher policy.

    Counterpart to install_block_rule.  Always returns True; emits a
    warn log so test artifacts can confirm the neutering took effect.
    """
    log(
        "tcp_punch_pcap.firewall.remove_block_rule({0}): "
        "firewall mutation disabled by dispatcher policy; "
        "relying on existing host firewall state.".format(int(port))
    )
    return True
