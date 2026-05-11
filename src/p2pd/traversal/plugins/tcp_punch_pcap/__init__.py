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

Plugin routing (set in p2pd/node/auto_connect.py phase2_tcp_punch):
  - dest is Windows-XP cross-machine + route_type=EXT_BIND ->
    tcp_punch_pcap
  - all other OS/route combinations -> legacy tcp_punch

Wire protocol reuses PunchMsg via the PunchPcapMsg subclass so the
plugin_loader can register a distinct wire name without forcing the
legacy plugin to know about us.

This plugin is intentionally minimal compared to tcp_punch: the bucket
math + NAT prediction in the legacy plugin (boundary_alloc.py,
nat_predict.py) is reused via composition where it makes sense and
skipped where it does not.  See main.py for the engine glue.
"""
