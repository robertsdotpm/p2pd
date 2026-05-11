"""tcp_punch_pcap_v2 -- parity port of tcp_punch over the pcap stack.

A second-generation pcap-driven TCP hole-punch plugin. Where the
original tcp_punch_pcap (sibling folder) is a minimal direct-
coordination simul-open prototype tied to the smoke-test driver,
this variant mirrors the full orchestration of the legacy
tcp_punch plugin:

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

Note: this is empirical / curiosity-grade. The folder lives
alongside the original tcp_punch_pcap rather than replacing it so
the cross_nat_pcap_smoke tests that reference the original keep
working. No merge plan / cascade-wiring decisions are made here.
"""
