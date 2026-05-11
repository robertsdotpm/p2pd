"""tcp_punch_pcap -- parity port of tcp_punch over the pcap stack.

A pcap-driven TCP hole-punch plugin that mirrors the full
orchestration of the legacy tcp_punch plugin:

  - Bucket-aligned punch_time via SysClock + compute_rendezvous
    (no coordinator-pushed wall-clock).
  - NAT-aware port prediction via NATPredictAlloc.
  - Multi-port SYN spray over the FAST_PUNCH_PARAMS window via the
    same boundary_port_alloc table tcp_punch uses.
  - Same wire protocol: tcp_punch.PunchMsg, plugin_name="tcp_punch"
    so it inter-ops with peers running plain tcp_punch.
  - PunchClient / Plugin shape matching tcp_punch/main.py.

The replacement substrate is the userspace pcap Connection from
aionetiface.net.pcap.tcp.conn -- N parallel Connection instances
sharing a single Backend handle through a fan-out reader that
demultiplexes captured frames by (local_ip, local_port, peer_ip,
peer_port).

Status: empirical research artefact. The plugin is DISABLED BY
DEFAULT and only activates when the node's conf opts in:

    conf["enable_pcap_tcp_punch"] = True

Without that key the plugin's setup() returns None and the node
falls through to the kernel-stack tcp_punch plugin as usual. With
it enabled, asymmetric cross-NAT interop with peers running plain
tcp_punch has been validated 5/5 green on Linux<->Linux runs via
tests/cross_nat_pcap_smoke/coordinator_v2_legacy.py.

Wire-level validation on non-Linux platforms is still partial:
XP-with-WinPcap + a permissive INPUT firewall surface is the
intended Windows-XP cross-NAT bypass target, but the responsibility
for opening the host firewall is the operator's, not the plugin's.
"""
