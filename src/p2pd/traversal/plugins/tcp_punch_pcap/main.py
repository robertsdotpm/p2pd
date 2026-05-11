"""Traversal plugin: pcap-driven TCP simultaneous-open hole punch.

Bypasses Windows-XP's tcpip.sys simul-open RST (see /home/x/projects/
p2pd/CLAUDE.md "Windows XP cross-NAT tcp_punch is not fixable from
user-space") by performing the SYN crossover in a pure-Python TCP
stack that talks to the NIC directly through libpcap / WinPcap /
Npcap.

Wire protocol:
    Reuses tcp_punch.PunchMsg verbatim -- ONE wire type for both
    plugins, so a peer running legacy tcp_punch on the kernel stack
    and a peer running tcp_punch_pcap on a userspace pcap stack speak
    the same bytes on the signal channel.  Critically, we DO NOT
    re-register PunchMsg under our own plugin name in proto_messages
    (that would create a "tcp_punch_pcap.PunchMsg" wire name and break
    interop with peers that have only tcp_punch installed).  We
    leave the wire-name registration to tcp_punch and simply import +
    use PunchMsg directly.

Routing eligibility (`route_types`):
    EXT_BIND only.  Same-LAN (NIC_BIND) and same-host (LOOPBACK_BIND)
    XP listeners do NOT need the userspace bypass -- they hit
    phase1_direct or phase2 with a working code path.  Only the
    EXT_BIND cross-NAT path triggers the tcpip.sys RST that this
    plugin exists to dodge.

Asymmetric routing:
    Each peer independently picks its local plugin based on ITS OWN
    OS (src_map.os).  The XP peer routes locally to tcp_punch_pcap;
    the non-XP peer routes locally to tcp_punch.  Both fire SYNs at
    the negotiated 4-tuples; on the wire they're indistinguishable.
    The XP-side userspace stack captures the inbound SYN via WinPcap
    before tcpip.sys gets to RST it (helped by a transient firewall
    block rule installed by punch_engine.pcap_punch_engine).
"""
import asyncio

from aionetiface import (
    log, EXT_BIND, TCP, SysClock, async_wrap_errors,
)

from ....protocol.proto_defs import P2P_PUNCH
from ...strategy_registry import register
from ...traversal_plugin import Plugin

from ..tcp_punch.proto import PunchMsg, TCP_PUNCH_REMOTE
from .punch_engine import pcap_punch_engine


def is_pcap_eligible_os(os_string):
    """True when our local OS is one where tcp_punch_pcap should run.

    Currently: Windows-XP and Windows-2000 -- the two NT-5 releases
    whose tcpip.sys exhibits the unfixable simul-open RST.  Other
    Windows versions (Vista / 7 / 8 / 10 / 11) use the kernel stack
    just fine and stick with legacy tcp_punch.
    """
    if not os_string:
        return False
    return (
        os_string.startswith("Windows-XP")
        or os_string.startswith("Windows-2000")
    )


@register(phase="punch")
class PunchPcapPlugin(Plugin):
    """TCP hole-punch over a userspace pcap stack -- XP cross-NAT path."""

    name = "tcp_punch_pcap"
    transport = TCP
    # See module docstring.  Same-LAN / same-host paths don't need
    # the bypass; only cross-WAN through a NAT does.
    route_types = (EXT_BIND,)
    # Tighter than tcp_punch's 180 s -- the userspace handshake either
    # converges in <2 s once both sides fire or it won't converge at
    # all (no NAT timer extension to play for).
    conf = {"timeout": 30}
    # IMPORTANT: do NOT register PunchMsg here.  tcp_punch already
    # registers it under the wire name "tcp_punch.PunchMsg".  Listing
    # it here would either collide (plugin_loader's collision check)
    # or, if the loader allowed it, create a second wire name
    # ("tcp_punch_pcap.PunchMsg") which would BREAK interop with
    # peers running only tcp_punch.  Both plugins share the single
    # wire registration owned by tcp_punch.
    proto_messages = ()

    @classmethod
    async def setup(cls, node):
        """Plugin loader entry point.

        Returns the plugin class itself when this node should run
        tcp_punch_pcap locally, or None when it shouldn't (so the
        plugin is silently disabled).  Disabled when:
          - punching is globally disabled via node.conf
          - the local OS is not Windows-XP / Windows-2000 (defence-
            in-depth: routing in auto_connect already only picks us
            when our OS qualifies, but we double-check here so a
            mis-routed plugin selection can't crash on an OS that
            doesn't need / can't run the pcap bypass)
          - the pcap backend (libpcap / WinPcap / Npcap) isn't
            available at runtime
        """
        if not node.conf.get("enable_punching", True):
            return None

        # OS gate -- only run on the NT-5 family.  os_id() returns
        # "Windows-XP" / "Windows-2000" / etc. on Windows.
        try:
            from aionetiface import os_id
            local_os = os_id()
        except ImportError:
            local_os = ""
        if not is_pcap_eligible_os(local_os):
            log("tcp_punch_pcap: local OS {0!r} is not NT-5 family; "
                "plugin not registered".format(local_os))
            return None

        try:
            from aionetiface.net.pcap import get_backend, PcapUnavailableError
        except ImportError:
            log("tcp_punch_pcap: aionetiface.net.pcap import failed; "
                "disabling plugin")
            return None
        try:
            factory = get_backend()
        except PcapUnavailableError as exc:
            log("tcp_punch_pcap: pcap unavailable ({0}); "
                "disabling plugin".format(exc))
            return None
        if not factory.available():
            log("tcp_punch_pcap: pcap factory reports unavailable; "
                "disabling plugin")
            return None
        log("tcp_punch_pcap: ready -- pcap library version: {0}".format(
            factory.library_version()))
        return cls

    async def run(self, reply=None):
        """Drive one round of the pcap-based punch protocol.

        Phase 3b scaffolding: the full bucket-aligned firing logic
        from tcp_punch/main.py is not duplicated here.  For the
        Windows-XP 2-VM smoke test this plugin treats the punch like
        a directly-coordinated simul-open:

          1. First call (reply=None): announce our preferred local
             port to the peer via PunchMsg, return.
          2. Second call (reply=PunchMsg): peer announced theirs.
             Fire pcap_punch_engine with simul=True.

        Wire format is the shared tcp_punch.PunchMsg.  We label our
        outgoing messages with plugin_name="tcp_punch" so the peer's
        signal dispatcher routes them to whichever plugin THAT peer
        is using for the wire-type "tcp_punch.PunchMsg" -- either
        legacy tcp_punch or tcp_punch_pcap.  The peer's inbound
        dispatcher applies the same OS-based override we do on our
        side (see traversal_manager.create_inbound_plugin).
        """
        my_port = (self.src or {}).get("port") or 0
        my_ip = (self.src or {}).get("ip") or ""

        if reply is None:
            msg = PunchMsg({
                "payload": {
                    "punch_mode": TCP_PUNCH_REMOTE,
                    "ntp": 0,
                    "mappings": [{"src": my_ip, "port": my_port}],
                    "nonce": "",
                    "tx_unix": 0,
                    "clock_uncertainty": 0.0,
                },
            })
            # Label as legacy tcp_punch on the wire.  The receiver's
            # inbound dispatcher will redirect to tcp_punch_pcap if
            # ITS local OS is NT-5; otherwise it stays in tcp_punch.
            # This keeps the two plugins fully interoperable.
            msg.meta.plugin_name = "tcp_punch"
            await self.send_signal(msg)
            return

        # We have the peer's reply -- extract their announced (ip, port).
        peer_mappings = reply.payload.mappings or []
        if not peer_mappings:
            log("tcp_punch_pcap: peer sent empty mappings list; aborting")
            if not self.result.done():
                self.result.set_result(None)
            return
        peer_entry = peer_mappings[0]
        peer_ip = peer_entry.get("src") if isinstance(peer_entry, dict) else None
        peer_port = peer_entry.get("port") if isinstance(peer_entry, dict) else None
        if not peer_ip or not peer_port:
            log("tcp_punch_pcap: malformed peer mapping {0}".format(peer_entry))
            if not self.result.done():
                self.result.set_result(None)
            return

        # Acknowledge with our mapping so the peer also fires.  Same
        # wire-name convention (tcp_punch) -- see comment above on
        # the initial send.
        ack = PunchMsg({
            "payload": {
                "punch_mode": TCP_PUNCH_REMOTE,
                "ntp": 0,
                "mappings": [{"src": my_ip, "port": my_port}],
                "nonce": "",
                "tx_unix": 0,
                "clock_uncertainty": 0.0,
            },
        })
        ack.meta.plugin_name = "tcp_punch"
        await async_wrap_errors(self.send_signal(ack))

        # Fire the pcap-driven punch.  The peer is doing the same
        # thing from their side -- either via their own pcap engine
        # (if they're also NT-5) or via their kernel TCP stack (if
        # they're a modern OS).  On the wire both look identical;
        # the userspace simul-open handler in aionetiface/net/pcap/
        # tcp/state.py expects a bare SYN to arrive on the same
        # four-tuple.
        nic_pcap_name = self.lookup_nic_pcap_name()
        log("tcp_punch_pcap: firing simul-open local={0}:{1} remote={2}:{3} iface={4}".format(
            my_ip, my_port, peer_ip, peer_port, nic_pcap_name))
        conn = await pcap_punch_engine(
            nic_pcap_name=nic_pcap_name,
            local_ip=my_ip,
            local_port=my_port,
            remote_ip=peer_ip,
            remote_port=peer_port,
            timeout=min(self.timeout or 30, 30),
        )
        if not self.result.done():
            self.result.set_result(conn)

    def lookup_nic_pcap_name(self):
        """Map self.nic to the pcap interface name.

        Best-effort.  On Unix the NIC's display name (eth0 / ens192 /
        vmx1) IS the pcap name.  On Windows the NIC carries the
        friendly name; we have to walk pcap_findalldevs and match by
        IP address.
        """
        nic = self.nic
        # Try .pcap_name first -- if the NIC layer ever grows one,
        # we want to honour it.
        explicit = getattr(nic, "pcap_name", None)
        if explicit:
            return explicit
        # Unix: NIC's name attribute matches pcap.
        import sys
        if not sys.platform.startswith("win"):
            return getattr(nic, "name", None) or ""
        # Windows: walk the pcap interface list and match by IP.
        from aionetiface.net.pcap import get_backend
        try:
            factory = get_backend()
        except Exception:
            return ""
        my_ip = (self.src or {}).get("ip") or ""
        for entry in factory.list_interfaces():
            if my_ip and my_ip in (entry.get("addresses") or ()):
                return entry["name"]
        return ""

    async def close(self):
        """Cancel any in-flight result future."""
        if not self.result.done():
            self.result.cancel()
