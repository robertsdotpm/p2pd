"""Pcap-driven simultaneous-open engine.

Runs in the main asyncio loop (no ProcessPoolExecutor needed -- the
userspace TCP layer in aionetiface/net/pcap is async-native and there
is no blocking-spray phase to push into a worker thread).

The flow on each side:
    1. Open a pcap Backend on the chosen NIC.
    2. Apply a tight BPF filter (tcp + the two ports involved) so the
       reader thread is not drowned in unrelated traffic.
    3. Construct a Connection in simul-open mode pointing at the peer
       (peer IP + peer port supplied via the PunchPcapMsg exchange).
    4. Wait up to plugin.timeout for ESTABLISHED.
    5. On success, return the userspace Connection.  The caller wraps
       it in a Pipe-shaped facade so the rest of auto_connect can
       use it like any other handshake result.

References:
  - aionetiface/src/aionetiface/net/pcap/tcp/conn.py for the
    Connection contract.
  - aionetiface/src/aionetiface/net/pcap/__init__.py for backend
    capability detection (PcapUnavailableError).
"""
import asyncio

from aionetiface import log
from aionetiface.net.pcap import (
    get_backend, PcapUnavailableError, PcapError,
)
from aionetiface.net.pcap.tcp.conn import Connection, ConnectionError2


async def pcap_punch_engine(nic_pcap_name, local_ip, local_port,
                             remote_ip, remote_port, timeout=10.0,
                             local_mac=None, remote_mac=None):
    """Run one userspace pcap simul-open punch attempt.

    Parameters
    ----------
    nic_pcap_name : str
        Interface name as exposed by pcap (libpcap on Unix -- "eth0",
        "ens192", "vmx1", "lo0"; on Windows -- the NPF device name
        e.g. "\\Device\\NPF_{GUID}").
    local_ip, local_port : peer's view of *us* (post-NAT external
        address when route_type=EXT_BIND, NIC IP when NIC_BIND).
    remote_ip, remote_port : our view of *them*.
    timeout : float
        Deadline for ESTABLISHED.  The PunchPlugin's plugin.timeout
        feeds this; tcp_punch's default of 180 s is very generous --
        userspace handshake converges in <1 s once both sides fire.
    local_mac, remote_mac : optional Ethernet MACs.  If unknown the
        Connection will use the ArpCache populated by sniffed ARP
        replies; passing them in skips the ARP probe latency.

    Returns
    -------
    Connection or None
        The userspace Connection on success; None on
        PcapUnavailableError / handshake timeout / RST.

    Failure modes mapped:
        PcapUnavailableError -> wpcap.dll missing -> returns None so
            the calling plugin can surface "pcap mode disabled" and
            fall back to legacy tcp_punch.
        PcapError on open -> NPF service not started / permission
            denied -> returns None.
        ConnectionError2 (handshake timeout or peer RST) -> returns
            None.
    """
    try:
        factory = get_backend()
    except PcapUnavailableError as exc:
        log("tcp_punch_pcap: pcap backend unavailable: {0}".format(exc))
        return None
    if not factory.available():
        log("tcp_punch_pcap: pcap factory reports unavailable")
        return None
    try:
        backend = factory.open(nic_pcap_name, timeout_ms=10)
    except PcapError as exc:
        log("tcp_punch_pcap: pcap_open_live({0}) failed: {1}".format(
            nic_pcap_name, exc,
        ))
        return None
    try:
        bpf = "tcp and port {0} and port {1}".format(local_port, remote_port)
        try:
            backend.set_filter(bpf)
        except PcapError as exc:
            log("tcp_punch_pcap: set_filter({0}) failed: {1}".format(bpf, exc))
            # Filter is optional -- recv() still works, just noisier.

        conn = Connection(backend, local_ip, local_mac=local_mac)
        await conn.start_active(
            remote_ip=remote_ip,
            remote_port=remote_port,
            local_port=local_port,
            remote_mac=remote_mac,
            simul=True,
        )
        try:
            await conn.wait_established(timeout=timeout)
        except ConnectionError2 as exc:
            log("tcp_punch_pcap: handshake failed: {0}".format(exc))
            try:
                await conn.close()
            except Exception:
                pass
            try:
                backend.close()
            except Exception:
                pass
            return None
        return conn
    except Exception as exc:
        log("tcp_punch_pcap: engine error: {0}".format(exc))
        try:
            backend.close()
        except Exception:
            pass
        return None
