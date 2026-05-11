"""Pcap-driven multi-port simul-open punch engine.

Mirrors the shape of tcp_punch.tcp_punch_engine.tcp_selector_punch_engine
but the substrate is N userspace pcap Connection instances instead of
N kernel TCP sockets:

    pre_connect_infos -> N Connection objects, each bound to one
        (src_port, dest_port) pair from puncher.port_allocs.
    sel               -> a PcapMuxReader that fans frames out to
        each Connection's MuxSubscriber by 4-tuple.
    sleep_until       -> the legacy PunchClient.sleep_until time
        synchroniser (NTP-quorum-backed via SysClock; bucket-aligned
        via compute_rendezvous from boundary_lib).
    connect_on_tcp_sockets -> Connection.start_active(simul=True)
        on each Connection, all calls issued back-to-back so the SYN
        frames go out within microseconds of each other.
    socket_event_monitor -> asyncio.wait on a set of futures backed by
        each Connection.established_event, returning the first
        Connection that reaches ESTABLISHED.

The engine returns the winning Connection (or None on miss). Unlike
the legacy plugin there is no ProcessPoolExecutor + reverse-loopback
bridge: the pcap Connection is already a coroutine, lives in the
main asyncio loop, and produces something the caller can Pipe-wrap
directly.

The engine is async; the legacy engine is sync because connect_ex on
a kernel socket blocks the event loop. The pcap path doesn't, so the
plugin can drive it directly in the asyncio loop -- no worker
thread, no selector_proxy bridge.
"""
import asyncio
import time

from aionetiface import log
from aionetiface.net.pcap import (
    PcapError, PcapUnavailableError, get_backend,
)
from aionetiface.net.pcap.tcp.conn import Connection, ConnectionError2

from .pcap_mux_reader import PcapMuxReader


def build_bpf_for_punch(port_allocs, local_ip, peer_ip):
    """Compose a BPF expression that captures every frame relevant to
    the spray.

    We want frames where either:
      - src=peer_ip dst=local_ip and (tcp dst port in our local set OR
        tcp src port in peer's predicted local set) -- the inbound
        side of any spray connection,
      OR
      - src=local_ip dst=peer_ip on the equivalent reverse direction
        (we capture our own outbound for retx visibility).

    BPF doesn't take port-sets cleanly; we OR them together. With
    NUM_PORTS=16 spreading over two buckets this is up to 32 ports
    per side -- still well under any per-handle BPF complexity limit.

    The filter is correctness-belt-and-suspenders -- the mux reader
    already does precise 5-tuple matching for delivery -- but cutting
    the kernel-to-userspace firehose down to TCP frames matching this
    flow makes the reader thread's job much lighter on a busy LAN.
    """
    local_ports = sorted(set(int(p.src_port) for p in port_allocs))
    peer_ports = sorted(set(int(p.dest_port) for p in port_allocs))
    local_port_clause = " or ".join(
        "tcp port {0}".format(p) for p in (local_ports + peer_ports)
    )
    host_clause = "(host {0} and host {1})".format(local_ip, peer_ip)
    if not local_port_clause:
        return "tcp and {0}".format(host_clause)
    return "tcp and {0} and ({1})".format(host_clause, local_port_clause)


async def pcap_setup_engine(nic_pcap_name, port_allocs, src_ip, dest_ip,
                             loop=None):
    """Open the backend, install a BPF, return (backend, mux, port_alloc_subs).

    port_alloc_subs is a list of (port_alloc, sub) pairs, parallel to
    pre_connect_infos in the legacy engine.
    """
    try:
        factory = get_backend()
    except PcapUnavailableError as exc:
        log("tcp_punch_pcap_v2: pcap unavailable: {0}".format(exc))
        return (None, None, [])
    if not factory.available():
        log("tcp_punch_pcap_v2: pcap factory not available")
        return (None, None, [])
    try:
        backend = factory.open(nic_pcap_name, timeout_ms=10)
    except PcapError as exc:
        log("tcp_punch_pcap_v2: pcap_open_live({0}) failed: {1}".format(
            nic_pcap_name, exc,
        ))
        return (None, None, [])

    bpf = build_bpf_for_punch(port_allocs, src_ip, dest_ip)
    try:
        backend.set_filter(bpf)
    except PcapError as exc:
        log("tcp_punch_pcap_v2: set_filter({0}) failed: {1}".format(bpf, exc))
        # filter is optional

    mux = PcapMuxReader(backend, loop=loop)

    port_alloc_subs = []
    for pa in port_allocs:
        ft = (src_ip, int(pa.src_port), dest_ip, int(pa.dest_port))
        sub = mux.subscribe(ft)
        port_alloc_subs.append((pa, sub))

    mux.start()
    return (backend, mux, port_alloc_subs)


async def spawn_connections(port_alloc_subs, src_ip, dest_ip, loop=None):
    """For each (port_alloc, sub) build a Connection and call start_active.

    Returns the list of Connection objects in port_allocs order so the
    caller can correlate winners back to the allocator entry.
    """
    conns = []
    for pa, sub in port_alloc_subs:
        conn = Connection(
            sub.backend, src_ip, loop=loop, reader=sub,
        )
        conns.append(conn)
        try:
            await conn.start_active(
                remote_ip=dest_ip,
                remote_port=int(pa.dest_port),
                local_port=int(pa.src_port),
                simul=True,
            )
        except Exception as exc:
            log("tcp_punch_pcap_v2: start_active({0}->{1}) failed: {2}".format(
                pa.src_port, pa.dest_port, exc,
            ))
    return conns


async def wait_first_established(conns, monitor_timeout=3.0):
    """Equivalent to socket_event_monitor: wait until one Connection
    reaches ESTABLISHED. Returns the winner Connection, or None on
    timeout.

    Mirrors the legacy "first ESTABLISHED + tiny grace period"
    behaviour from socket_event_monitor: as soon as one Connection
    fires the event, give the other tuples ~50 ms to catch up (so we
    can pick the canonical winner via the master/slave selection
    later if needed), then return.
    """
    if not conns:
        return None

    # Build one wait_for-style awaitable per connection.
    pending = set()
    waiters = {}
    loop = asyncio.get_event_loop()
    for conn in conns:
        task = loop.create_task(conn.established_event.wait())
        pending.add(task)
        waiters[task] = conn

    start = time.monotonic()
    end = start + monitor_timeout
    winners = []
    first_at = None
    grace = 0.050
    try:
        while pending:
            # Compute the wait deadline. Once a first winner has been
            # observed, cap the remaining wait to the small grace
            # period so stragglers in the same fire have ~50 ms to
            # converge but we don't burn the whole monitor_timeout.
            now = time.monotonic()
            if first_at is None:
                remaining = end - now
            else:
                remaining = (first_at + grace) - now
            if remaining <= 0:
                break
            done, pending = await asyncio.wait(
                pending,
                timeout=remaining,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for d in done:
                conn = waiters.pop(d, None)
                if conn is None:
                    continue
                if not d.cancelled() and conn.state is not None \
                        and conn.state.is_established():
                    winners.append(conn)
                    if first_at is None:
                        first_at = time.monotonic()
            # If nothing completed and we ran past the deadline, exit.
            if not done:
                break
    finally:
        # Cancel anything still pending.
        for t in pending:
            t.cancel()

    if not winners:
        log("tcp_punch_pcap_v2: monitor done; no ESTABLISHED in {0:.3f}s".format(
            time.monotonic() - start,
        ))
        return None
    print("[ENGINE-PCAPV2] monitor done winners={0}/{1} elapsed={2:.3f}s".format(
        len(winners), len(conns), time.monotonic() - start,
    ), flush=True)
    return winners[0]


async def cleanup_losers(conns, winner):
    """Close every Connection that didn't win."""
    for c in conns:
        if c is winner:
            continue
        try:
            await c.close()
        except Exception:
            pass


async def pcap_selector_punch_engine(
        nic_pcap_name, port_allocs, src_ip, dest_ip,
        f_sleep_until_async, params=None, loop=None,
):
    """Async parity of tcp_selector_punch_engine, pcap substrate.

    Parameters mirror the legacy engine signature but in async form:

        nic_pcap_name : str -- pcap iface name (libpcap "eth0" or
            Windows "\\Device\\NPF_{GUID}").
        port_allocs   : list of punch_defs.PortAlloc (src_port, dest_port).
        src_ip, dest_ip : str -- bind / peer IPs.
        f_sleep_until_async : coroutine -- must await until the
            bucket-aligned punch_time. The caller wraps PunchClient.sleep_until
            (a blocking sleep) in run_in_executor; this engine awaits the
            coroutine here without owning the synchronisation strategy.
        params : optional punch param dict (FAST_PUNCH_PARAMS shape).

    Returns
    -------
    Connection or None : the winning userspace Connection on success.
    """
    if params is not None:
        monitor_timeout = params.get("monitor_timeout", 3.0)
        connect_timeout = params.get("connect_timeout", 3.0)
    else:
        monitor_timeout = 3.0
        connect_timeout = 3.0

    print("[ENGINE-PCAPV2] enter src_ip={0} dest_ip={1} n_allocs={2} "
          "monitor={3}s".format(
              src_ip, dest_ip, len(port_allocs), monitor_timeout,
          ), flush=True)

    backend = None
    mux = None
    conns = []
    try:
        backend, mux, port_alloc_subs = await pcap_setup_engine(
            nic_pcap_name, port_allocs, src_ip, dest_ip, loop=loop,
        )
        if backend is None:
            log("tcp_punch_pcap_v2: pcap_setup_engine returned no backend")
            return None
        log("tcp_punch_pcap_v2: opened {0} subscribers on iface {1}".format(
            len(port_alloc_subs), nic_pcap_name,
        ))

        # Bucket-aligned wait. f_sleep_until_async is a coroutine that
        # blocks until the rendezvous moment.
        print("[ENGINE-PCAPV2] sleep_until_async enter", flush=True)
        await f_sleep_until_async()
        print("[ENGINE-PCAPV2] sleep_until_async done; firing SYNs", flush=True)

        # Burst-start every Connection. start_active queues the SYN
        # frame and returns immediately; the SYN is on the wire within
        # one flush_outbox() call per Connection.
        conns = await spawn_connections(
            port_alloc_subs, src_ip, dest_ip, loop=loop,
        )

        # Monitor for the first ESTABLISHED.
        winner = await wait_first_established(
            conns, monitor_timeout=monitor_timeout,
        )

        if winner is None:
            log("tcp_punch_pcap_v2: spray missed; closing all conns")
            await cleanup_losers(conns, None)
            return None

        # Close losers; return winner.
        await cleanup_losers(conns, winner)
        return winner
    finally:
        # The winner Connection keeps the backend/mux alive until the
        # caller closes it. If there's no winner, tear everything down.
        if mux is not None and (not conns or not any(
                c.state is not None and c.state.is_established()
                for c in conns)):
            try:
                mux.stop()
            except Exception:
                pass
            if backend is not None:
                try:
                    backend.close()
                except Exception:
                    pass
