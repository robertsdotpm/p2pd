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
        log("tcp_punch_pcap: pcap unavailable: {0}".format(exc))
        return (None, None, [])
    if not factory.available():
        log("tcp_punch_pcap: pcap factory not available")
        return (None, None, [])
    try:
        backend = factory.open(nic_pcap_name, timeout_ms=10)
    except PcapError as exc:
        log("tcp_punch_pcap: pcap_open_live({0}) failed: {1}".format(
            nic_pcap_name, exc,
        ))
        return (None, None, [])

    bpf = build_bpf_for_punch(port_allocs, src_ip, dest_ip)
    try:
        backend.set_filter(bpf)
    except PcapError as exc:
        log("tcp_punch_pcap: set_filter({0}) failed: {1}".format(bpf, exc))
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
            log("tcp_punch_pcap: start_active({0}->{1}) failed: {2}".format(
                pa.src_port, pa.dest_port, exc,
            ))
    return conns


async def wait_first_established(conns, monitor_timeout=3.0):
    """Equivalent to socket_event_monitor: wait the FULL monitor_timeout
    collecting all Connections that reach ESTABLISHED, then return the
    set (possibly empty).

    Earlier behaviour exited ~50 ms after the FIRST ESTABLISHED event.
    That cut the converged set down to whichever Connections happened
    to fire SYN+ACK in the first burst -- 7/20 on real cross-NAT runs
    -- which then mismatched the legacy peer's canonical winner pick
    (legacy's kernel collects ALL successes inside the full 3 s monitor
    window). Mismatched picks closed each side's chosen 4-tuple and
    the slave's race for `$` timed out.

    Waiting the full window mirrors legacy's socket_event_monitor:
    both peers see the same 4-tuple set, the sort key is symmetric,
    so sorted_conns[-1] picks the same canonical winner on both sides.
    """
    if not conns:
        return []

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
    try:
        while pending:
            now = time.monotonic()
            remaining = end - now
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
            # If nothing completed before timeout, exit.
            if not done:
                break
    finally:
        # Cancel anything still pending.
        for t in pending:
            t.cancel()

    if not winners:
        log("tcp_punch_pcap: monitor done; no ESTABLISHED in {0:.3f}s".format(
            time.monotonic() - start,
        ))
        return []
    return winners


def sort_key_ft(conn):
    """Sort key matching legacy: sort by (local_ip, local_port,
    remote_ip, remote_port) so master.pop() picks a deterministic
    canonical winner across both peers.

    Legacy `choose_winning_tcp_sock` does `sock_list.pop()` on the
    `successful` list which was built in spawn order, then mutated by
    the engine's add-on-established. To get a deterministic winner
    that both peers agree on, we sort by 4-tuple and pop the last
    element. Both peers see the SAME set of 4-tuples (mirror images
    on src/dst, but mirroring preserves sort order across peers if we
    use the canonical 4-tuple shape) -- so both peers pop the same
    Connection.

    The canonical shape we sort by is (min(ip), max(ip), min(port),
    max(port))-ish? No: we sort by the local 4-tuple as observed on
    THIS peer. Both peers must agree, so we instead sort by the
    "peer-symmetric" tuple: sorted((local_ip, local_port), (remote_ip,
    remote_port)). Each side computes the same pair-set, so both
    agree on the canonical ordering even though their local view of
    "local" and "remote" is swapped.
    """
    ft = getattr(conn, "ft", None)
    if ft is None:
        return ((), ())
    a = (ft.local_ip, int(ft.local_port))
    b = (ft.remote_ip, int(ft.remote_port))
    pair = tuple(sorted((a, b)))
    return pair


async def choose_canonical_winner(established, src_ip, dest_ip,
                                  slave_timeout=4.0):
    """Master/slave canonical-winner handshake -- pcap mirror of
    legacy ``choose_winning_tcp_sock``.

    Parameters
    ----------
    established : list of Connection
        All Connections that reached ESTABLISHED in the grace window.
    src_ip, dest_ip : str
        Our local IP and the peer IP, compared as strings to decide
        master vs slave (master = my_ip > peer_ip), matching legacy.
    slave_timeout : float
        How long the slave waits for the master's ``$`` byte before
        giving up. Mirrors legacy's 5s wait_for_first_with_data.

    Returns
    -------
    Connection or None : the canonical winner both peers agree on,
        or None if the handshake failed (no `$` observed, or the
        master's send raised). On failure, ALL Connections in
        established are closed and the caller should set result(None).
    """
    if not established:
        return None

    is_master = src_ip > dest_ip
    role = "master" if is_master else "slave"
    sorted_conns = sorted(established, key=sort_key_ft)
    log("tcp_punch_pcap: canonical-winner handshake role={0} "
        "n_established={1}".format(role, len(sorted_conns)))

    if is_master:
        # Mirror legacy `sock_list.pop()` after the deterministic sort.
        winner = sorted_conns[-1]
        winner_ft = getattr(winner, "ft", None)
        winner_key = winner_ft.key() if winner_ft is not None else None
        try:
            await winner.send(b"$")
            log("tcp_punch_pcap: master sent $ on {0}".format(winner_key))
        except Exception as exc:
            log("tcp_punch_pcap: master send($) failed: {0}".format(exc))
            for c in sorted_conns:
                try:
                    await c.close()
                except Exception:
                    pass
            return None
        return winner

    # Slave: race recv(1) across every established Connection.
    # The first byte each conn delivers is consumed from its read_buf
    # by Connection.recv -- so when we wrap the winner in PipeShim
    # later, the application's first recv(SUB_ALL) won't see the `$`.
    loop = asyncio.get_event_loop()
    tasks = {}
    for c in sorted_conns:
        t = loop.create_task(c.recv(1, timeout=slave_timeout))
        tasks[t] = c

    winner = None
    winner_byte = None
    start = time.monotonic()
    pending = set(tasks.keys())
    try:
        while pending and winner is None:
            done, pending = await asyncio.wait(
                pending,
                timeout=slave_timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                break
            for d in done:
                c = tasks.get(d)
                if c is None:
                    continue
                try:
                    data = d.result()
                except Exception as exc:
                    log("tcp_punch_pcap: slave recv raised on "
                        "{0}: {1}".format(
                            getattr(c, "ft", None)
                            and c.ft.key(), exc,
                        ))
                    continue
                if data:
                    winner = c
                    winner_byte = data
                    break
    finally:
        # Cancel still-pending recvs.
        for t in pending:
            t.cancel()

    elapsed = time.monotonic() - start
    if winner is None:
        log("tcp_punch_pcap: slave timed out waiting for $ "
            "({0:.3f}s)".format(elapsed))
        for c in sorted_conns:
            try:
                await c.close()
            except Exception:
                pass
        return None

    winner_ft = getattr(winner, "ft", None)
    winner_key = winner_ft.key() if winner_ft is not None else None
    log("tcp_punch_pcap: slave got {0} on {1}".format(
        repr(winner_byte), winner_key,
    ))
    return winner


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


    backend = None
    mux = None
    conns = []
    try:
        backend, mux, port_alloc_subs = await pcap_setup_engine(
            nic_pcap_name, port_allocs, src_ip, dest_ip, loop=loop,
        )
        if backend is None:
            log("tcp_punch_pcap: pcap_setup_engine returned no backend")
            return None
        log("tcp_punch_pcap: opened {0} subscribers on iface {1}".format(
            len(port_alloc_subs), nic_pcap_name,
        ))

        # Bucket-aligned wait. f_sleep_until_async is a coroutine that
        # blocks until the rendezvous moment.
        await f_sleep_until_async()

        # Burst-start every Connection. start_active queues the SYN
        # frame and returns immediately; the SYN is on the wire within
        # one flush_outbox() call per Connection.
        conns = await spawn_connections(
            port_alloc_subs, src_ip, dest_ip, loop=loop,
        )

        # Monitor for ESTABLISHED Connections. Returns the list of
        # all Connections that converged within the grace window.
        established = await wait_first_established(
            conns, monitor_timeout=monitor_timeout,
        )

        if not established:
            log("tcp_punch_pcap: spray missed; closing all conns")
            await cleanup_losers(conns, None)
            return None

        # Canonical-winner handshake: both peers must converge on the
        # SAME 4-tuple. Without this step v2 picks established[0]
        # while legacy uses `$` master/slave -- mismatch closes each
        # side's chosen winner.
        winner = await choose_canonical_winner(
            established, src_ip, dest_ip,
        )

        if winner is None:
            log("tcp_punch_pcap: canonical-winner handshake failed; "
                "all conns closed")
            # choose_canonical_winner already closed the established
            # set on failure; close any spawned-but-never-established
            # conns too.
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
