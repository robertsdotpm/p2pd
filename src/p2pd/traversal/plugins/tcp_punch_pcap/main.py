"""Traversal plugin: pcap-driven TCP simultaneous-open hole punch.

Bypasses Windows-XP's tcpip.sys simul-open RST (see /home/x/projects/
p2pd/CLAUDE.md "Windows XP cross-NAT tcp_punch is not fixable from
user-space") by performing the SYN crossover in a pure-Python TCP
stack that talks to the NIC directly through libpcap / WinPcap /
Npcap.

Wire protocol:
    Reuses PunchMsg verbatim (via the PunchPcapMsg subclass) so the
    legacy plugin's payload format -- mappings, NTP punch time, clock
    uncertainty -- is shared.  Receiver dispatch is keyed off the
    wire name "tcp_punch_pcap.PunchPcapMsg", which plugin_loader
    derives at install time.

Routing eligibility (`route_types`):
    EXT_BIND only.  Same-LAN (NIC_BIND) and same-host (LOOPBACK_BIND)
    XP listeners do NOT need the userspace bypass -- they hit
    phase1_direct or phase2 with a working code path.  Only the
    EXT_BIND cross-NAT path triggers the tcpip.sys RST that this
    plugin exists to dodge.

This file deliberately mirrors the structure of
plugins/tcp_punch/main.py so a future merge / refactor can fold
the two into a single plugin parameterised by transport backend.
"""
import asyncio

from aionetiface import (
    log, EXT_BIND, TCP, SysClock, async_wrap_errors,
)

from ....protocol.proto_defs import P2P_PUNCH
from ...strategy_registry import register
from ...traversal_plugin import Plugin

from .proto import PunchPcapMsg
from .punch_engine import pcap_punch_engine


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
    proto_messages = (
        (PunchPcapMsg, P2P_PUNCH, 20),
    )

    @classmethod
    async def setup(cls, node):
        """Plugin loader entry point.

        Returns the plugin class itself when the host has a working
        pcap library (so plugin_loader uses it as the constructor),
        or None when wpcap.dll / libpcap.so is missing (so the plugin
        is silently disabled and auto_connect routes XP destinations
        the way it did before this branch landed).
        """
        if not node.conf.get("enable_punching", True):
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

        Phase 3 scaffolding: the full bucket-aligned firing logic
        from tcp_punch/main.py is not duplicated here.  For the
        Windows-XP 2-VM smoke test this plugin treats the punch like
        a directly-coordinated simul-open:

          1. First call (reply=None): announce our preferred local
             port to the peer via PunchPcapMsg, return that message.
          2. Second call (reply=PunchPcapMsg): peer announced theirs.
             Fire pcap_punch_engine with simul=True.

        This matches what the XP smoke test in p2pd_test_run/
        actually needs (LAN address pair, no NAT mapping prediction).
        Full bucket-aligned firing for cross-WAN XP listeners is
        Phase 4 work.
        """
        # Minimal first-message: announce src_ip:src_port -- since this
        # plugin only fires on EXT_BIND, those are the post-NAT externals
        # that the manager has already resolved.
        my_port = (self.src or {}).get("port") or 0
        my_ip = (self.src or {}).get("ip") or ""

        if reply is None:
            msg = PunchPcapMsg({
                "payload": {
                    "punch_mode": 2,  # tcp_punch.proto.TCP_PUNCH_REMOTE
                    "ntp": 0,
                    "mappings": [{"src": my_ip, "port": my_port}],
                    "nonce": "",
                    "tx_unix": 0,
                    "clock_uncertainty": 0.0,
                },
            })
            msg.meta.plugin_name = "tcp_punch_pcap"
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

        # Acknowledge with our mapping so the peer also fires.
        ack = PunchPcapMsg({
            "payload": {
                "punch_mode": 2,
                "ntp": 0,
                "mappings": [{"src": my_ip, "port": my_port}],
                "nonce": "",
                "tx_unix": 0,
                "clock_uncertainty": 0.0,
            },
        })
        ack.meta.plugin_name = "tcp_punch_pcap"
        await async_wrap_errors(self.send_signal(ack))

        # Fire the pcap-driven punch.  The peer is doing the same thing
        # from their side; the userspace simul-open handler in
        # aionetiface/net/pcap/tcp/state.py expects a bare SYN to arrive
        # on the same four-tuple.
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
