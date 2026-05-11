"""tcp_punch_pcap -- userspace-pcap TCP hole-punch traversal plugin.

A parallel implementation of the standard `tcp_punch` plugin that
performs the TCP simultaneous-open handshake through a pure-Python
userspace TCP stack driven over libpcap / WinPcap / Npcap instead of
the host kernel's tcpip stack.

The motivation is the Windows-XP cross-NAT tcp_punch failure path
documented in /home/x/projects/p2pd/CLAUDE.md: XP's tcpip.sys RSTs
the connection ~140 ms after a simul-open handshake completes on
the wire.  Hamachi worked around the same bug with a signed NDIS
filter driver; we work around it from user-space by talking to the
NIC directly through libpcap / WinPcap, never letting tcpip.sys see
the simul-open SYN crossover.

Wire-format design (do NOT redesign without rereading this):
  Both plugins (tcp_punch and tcp_punch_pcap) share ONE wire message
  type: tcp_punch.PunchMsg.  tcp_punch_pcap does NOT register its
  own wire-name -- it leaves the proto_messages tuple empty and
  imports PunchMsg from ..tcp_punch.proto for direct use.  This
  guarantees interop: a peer running tcp_punch on a Linux kernel
  stack and a peer running tcp_punch_pcap on a userspace pcap stack
  exchange the same bytes on the signal channel.

Routing (asymmetric, based on LOCAL OS only):
  Each peer independently picks its plugin based on its own OS
  (src_map.os in auto_connect.phase2_tcp_punch, or os_id() in
  traversal_manager.create_inbound_plugin for inbound).
    - LOCAL OS starts with "Windows-XP" or "Windows-2000" AND
      route_type=EXT_BIND AND tcp_punch_pcap is installed
        -> tcp_punch_pcap on this side
    - any other case -> tcp_punch (kernel stack)
  The peer's choice is independent of ours.  A Linux connector
  paired with an XP listener: Linux picks tcp_punch, XP picks
  tcp_punch_pcap.  Both fire SYNs simultaneously; on the wire they
  look identical.

tcpip.sys interference avoidance:
  XP's tcpip.sys may RST an inbound SYN that doesn't match a kernel
  socket.  punch_engine.pcap_punch_engine installs a transient
  Windows Firewall inbound block rule on the predicted local TCP
  port BEFORE injecting the first frame, and removes the rule in
  a finally: clause so a crash never leaves the firewall stuck.
  See firewall.py for the netsh wrapper.
"""
