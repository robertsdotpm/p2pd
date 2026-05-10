"""
Random-probe UDP machinery (Tailscale-style symmetric NAT traversal).

Two halves:

  run_non_sym_side(...)  -- the non-symmetric peer.  Could be open
                         internet, full cone, restricted, or
                         port-restricted -- anything where outbound
                         port mapping is predictable per source.
                         Opens *one* UDP socket bound to a known
                         local port; fires N probes at random
                         destination ports on the symmetric peer's
                         external IP; listens on that same socket
                         for the first reply that bears the shared
                         magic+nonce.

  run_symmetric_side(...) -- the symmetric peer.  Opens N UDP
                         sockets each bound to a different local
                         source port; fires *one* probe from each
                         at the cone peer's known (ext_ip,
                         ext_port); listens on every socket and
                         returns the first one that hears back.

Wire format per probe (always exactly PROBE_LEN bytes):
    magic (4)  nonce (16)  role (1)  probe_index (2 BE)

Successful return value from either side is a dict
    {"sock": <connected socket>, "peer": (ip, port)}
which the caller can wrap in a Pipe / build a node-protocol
session on top of.

The functions are deliberately transport-agnostic at the asyncio
level -- we use raw sockets + sock_recv so the caller doesn't have
to plumb a Pipe through a process pool just to fire 256 datagrams.
"""

import asyncio
import random
import socket
import struct
import time

from aionetiface.net.address import resolve_dest_tup

from .random_probe_defs import (
    DEFAULT_PROBE_COUNT,
    PROBE_IDX_CONFIRM,
    PROBE_LEN,
    PROBE_LISTEN_TIMEOUT,
    PROBE_MAGIC,
    PROBE_PORT_HI,
    PROBE_PORT_LO,
    ROLE_CONE,
    ROLE_SYM,
)


# ─────────────────────────────────────────────────────────────────
# Wire format
# ─────────────────────────────────────────────────────────────────


def encode_probe(nonce, role, idx):
    """Pack one probe datagram.

    *nonce* must be exactly 16 bytes; *role* must be ROLE_CONE or
    ROLE_SYM; *idx* is a per-probe sequence number in [0, 65535].
    The result is always PROBE_LEN bytes so receivers can skip
    anything that isn't an exact length match without parsing.
    """
    if len(nonce) != 16:
        raise ValueError("probe nonce must be 16 bytes")
    if role not in (ROLE_CONE, ROLE_SYM):
        raise ValueError("probe role must be ROLE_CONE or ROLE_SYM")
    return PROBE_MAGIC + nonce + role + struct.pack("!H", idx & 0xFFFF)


def decode_probe(data, want_nonce):
    """
    Validate that *data* is one of *our* probes for the session
    identified by *want_nonce*.  Returns the parsed fields on hit,
    or None when the datagram doesn't belong to us (wrong length,
    bad magic, wrong nonce, unknown role).
    """
    if len(data) != PROBE_LEN:
        return None
    if data[:4] != PROBE_MAGIC:
        return None
    if data[4:20] != want_nonce:
        return None
    role = data[20:21]
    if role not in (ROLE_CONE, ROLE_SYM):
        return None
    idx = struct.unpack("!H", data[21:23])[0]
    return {"role": role, "idx": idx}


# ─────────────────────────────────────────────────────────────────
# Probe-port set generation
# ─────────────────────────────────────────────────────────────────


def random_probe_ports(count, rng=None):
    """Return *count* distinct random ports in [PROBE_PORT_LO, PROBE_PORT_HI].

    The cone uses these as destination ports it fires at; the
    symmetric side uses them as source ports it binds from.  Either
    way they need to be unique within the side's own probe set --
    duplicates would just waste probes.
    """
    if rng is None:
        rng = random.SystemRandom()
    span = PROBE_PORT_HI - PROBE_PORT_LO + 1
    if count > span:
        raise ValueError(
            "probe count {0} exceeds available port range {1}".format(count, span)
        )
    return rng.sample(range(PROBE_PORT_LO, PROBE_PORT_HI + 1), count)


# ─────────────────────────────────────────────────────────────────
# Socket helpers
# ─────────────────────────────────────────────────────────────────


def make_udp_socket(
    bind_ip,
    bind_port=0,
    interface=None,
):
    """
    Create a non-blocking UDP socket bound to (bind_ip, bind_port).

    On a multi-NIC host plain ``bind((ip, port))`` is *not* enough
    to force packets to egress through the right interface --
    Linux routes by destination IP, not source bind, so packets
    sourced from NIC2's IP can still leave via NIC1's gateway and
    hairpin.  When *interface* is provided and isn't the default
    NIC, this also sets SO_BINDTODEVICE (sockopt 25) which pins
    egress to that interface regardless of the routing table.
    Mirrors aionetiface's socket_factory.

    Uses SO_REUSEADDR (and SO_REUSEPORT where available) so the
    symmetric side can bind many sockets in close succession even
    if the kernel hasn't yet released TIME_WAIT entries from a
    previous run.
    """
    fam = socket.AF_INET6 if ":" in bind_ip else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (OSError, AttributeError):
            pass

    # Force interface egress.  Skipped on Windows (no
    # SO_BINDTODEVICE) and when the NIC is the default route (no
    # need to override + may need root on Linux for non-default).
    if interface is not None and not _IS_WINDOWS:
        try:
            af = socket.AF_INET6 if ":" in bind_ip else socket.AF_INET
            is_default = interface.is_default(af)
        except (OSError, AttributeError):
            is_default = True
        if not is_default:
            iface_bytes = b""
            try:
                # Encode the interface id (string for real NICs,
                # int for synthetic loopback FakeInterfaces -- the
                # latter just won't trigger this path because
                # is_default is True for them).
                iface_bytes = (
                    interface.id
                    if isinstance(interface.id, bytes)
                    else str(interface.id).encode("ascii", "ignore")
                )
                if iface_bytes:
                    s.setsockopt(socket.SOL_SOCKET, 25, iface_bytes)
            except OSError:
                # Most likely EPERM (Linux SO_BINDTODEVICE needs
                # CAP_NET_RAW / root).  The bind still happens, but
                # egress falls back to the default route -- on a
                # multi-NIC host that means packets sourced from a
                # non-default NIC's IP can leave through the wrong
                # interface and hairpin.  The plugin doesn't fail
                # hard on this -- the algorithm will just converge
                # via the default-route NIC and probably hit
                # self-loop guards.
                pass

    s.setblocking(False)
    s.bind((bind_ip, bind_port))
    return s


_IS_WINDOWS = False
try:
    import sys as _sys
    _IS_WINDOWS = _sys.platform == "win32"
except ImportError:
    pass


def normalize_ip6(addr):
    """Return canonical (compressed, no leading zeros) IPv6 address string.

    Strips any %scope suffix before normalising so the result is safe
    to pass to sendto 2-tuples and string comparisons alike.  IPv4
    addresses are returned unchanged.
    """
    if ":" not in addr:
        return addr
    try:
        import ipaddress
        return str(ipaddress.ip_address(addr.split("%")[0]))
    except (ValueError, AttributeError):
        return addr


def close_all(socks):
    """Close every socket; never raises (best-effort cleanup)."""
    for s in socks:
        try:
            s.close()
        except OSError:
            pass


def drain_probe_residue(sock, want_nonce):
    """Drain in-flight probe datagrams from *sock* without blocking.

    Uses MSG_PEEK to look without consuming -- only consumes
    datagrams that decode as one of *our* probes.  Real user
    payload at the head of the queue is left alone for the Pipe
    layer to deliver (a plain recvfrom would consume it AND
    leave us with no way to re-queue, eating user data).

    Instant version -- stops at the first non-probe at the head.
    See async_drain_probe_residue for the duration-based variant.
    """
    drained = 0
    sock.setblocking(False)
    while True:
        try:
            data, _addr = sock.recvfrom(4096, socket.MSG_PEEK)
        except (BlockingIOError, InterruptedError):
            break
        except OSError:
            break
        if decode_probe(data, want_nonce) is None:
            break
        try:
            sock.recvfrom(4096)
        except (BlockingIOError, OSError):
            break
        drained += 1
    return drained


async def async_drain_probe_residue(
    sock,
    want_nonce,
    duration=1.0,
):
    """Drain probe-format datagrams from *sock* for *duration* seconds.

    Uses MSG_PEEK to look at the head of the kernel queue
    *without consuming* -- only consumes datagrams that decode
    as one of *our* probes.  Real user payload that arrives
    during the drain window stays queued and is delivered to the
    Pipe layer as expected.

    The instant variant only catches what the kernel already has
    queued.  On a real cross-internet path (CGNAT, mobile carrier
    in the loop) the symmetric peer's 256-pack arrives spread
    over hundreds of ms -- by the time the algorithm sets the
    result, more probes are still in flight.  This variant keeps
    consuming any matching probe datagrams for the full duration
    so late arrivers get silently dropped instead of being
    delivered as data on the user's pipe.
    """
    if hasattr(asyncio, "get_running_loop"):
        loop = asyncio.get_running_loop()
    else:
        loop = asyncio.get_event_loop()
    deadline = loop.time() + duration
    drained = 0
    sock.setblocking(False)
    while loop.time() < deadline:
        # Peek first.  If the head is a probe, consume it.  If
        # it's anything else, leave it for the application.
        try:
            data, _addr = sock.recvfrom(4096, socket.MSG_PEEK)
        except (BlockingIOError, InterruptedError):
            await asyncio.sleep(0.02)
            continue
        except OSError:
            break
        if decode_probe(data, want_nonce) is None:
            # Real user data is at the head of the queue.  Stop
            # draining so the Pipe layer can deliver it.  Don't
            # busy-loop -- yield control briefly in case more
            # late probes are coming behind it (we'll catch
            # those next iteration if the user data also gets
            # consumed by the Pipe quickly).
            await asyncio.sleep(0.05)
            continue
        # It's a probe.  Consume it for real.
        try:
            sock.recvfrom(4096)
            drained += 1
        except (BlockingIOError, OSError):
            break
    return drained


def sync_stun_discover_mapping(
    sock,
    stun_server,
    af,
    timeout=3.0,
    retries=3,
):
    """Sync version of stun_discover_mapping.

    No asyncio.  Uses select() for the wait, plain recvfrom for
    delivery.  Run from a thread executor or after switching the
    sock to plain blocking mode.  Leaves the sock in non-blocking
    mode at exit.
    """
    from aionetiface.protocol.stun.stun_defs import (
        RFC5389, STUNMsg, STUNMsgTypes, STUNMsgCodes,
    )
    from aionetiface.protocol.stun.stun_utils import stun_proto
    import select as select_mod

    sock.setblocking(False)
    for _ in range(retries):
        msg = STUNMsg(
            msg_type=STUNMsgTypes.Binding,
            msg_code=STUNMsgCodes.Request,
            mode=RFC5389,
        )
        txid = bytes(msg.txn_id)
        try:
            sock.sendto(msg.pack(), stun_server)
        except OSError:
            return None
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                ready, _, _ = select_mod.select([sock], [], [], remaining)
            except (OSError, select_mod.error):
                break
            if not ready:
                break
            try:
                data, _addr = sock.recvfrom(2048)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                return None
            if len(data) < 20 or bytes(data[8:20]) != txid:
                continue
            try:
                reply, _ = stun_proto(data, af)
            except (ValueError, IndexError):
                continue
            rtup = getattr(reply, "rtup", None)
            if rtup is None:
                continue
            return (str(rtup[0]), int(rtup[1]))
    return None


async def stun_discover_mapping(
    loop,
    sock,
    stun_server,
    af,
    timeout=3.0,
    retries=3,
):
    """
    Send a STUN binding request via the *already-bound* UDP socket
    and return the (mapped_ip, mapped_port) the server reports, or
    None on timeout / parse failure.

    The socket stays under our control -- no Pipe wrapping, no
    create_datagram_endpoint -- so the algorithm can keep using
    raw sendto / recvfrom_async on it after this call returns.
    The NAT mapping installed by this round-trip (local_ip,
    local_port -> wan_ip, mapped_port) is exactly what the peer
    needs to aim at, so we want the same socket to keep that
    mapping alive through the fire phase.

    Imports the STUN message machinery lazily so plugin import
    isn't load-bearing on aionetiface's STUN package.
    """
    from aionetiface.protocol.stun.stun_defs import (
        RFC5389, STUNMsg, STUNMsgTypes, STUNMsgCodes,
    )
    from aionetiface.protocol.stun.stun_utils import stun_proto

    for _ in range(retries):
        msg = STUNMsg(
            msg_type=STUNMsgTypes.Binding,
            msg_code=STUNMsgCodes.Request,
            mode=RFC5389,
        )
        txid = bytes(msg.txn_id)
        try:
            sock.sendto(msg.pack(), stun_server)
        except OSError:
            return None

        deadline = loop.time() + timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                data, _addr = await asyncio.wait_for(
                    recvfrom_async(loop, sock),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                break
            except OSError:
                return None

            # Match the response to our txid.  Anything else is a
            # stray packet and is ignored.
            if len(data) < 20 or bytes(data[8:20]) != txid:
                continue
            try:
                reply, _ = stun_proto(data, af)
            except (ValueError, IndexError):
                continue
            rtup = getattr(reply, "rtup", None)
            if rtup is None:
                continue
            return (str(rtup[0]), int(rtup[1]))
    return None


async def recvfrom_async(loop, sock, bufsize=2048):
    """
    Async UDP recvfrom that works on Python 3.5+.

    asyncio.AbstractEventLoop.sock_recvfrom only landed in Python
    3.11.  We install an add_reader callback that does the
    non-blocking recvfrom and resolves a Future, which is the
    portable primitive supported back to 3.5.
    """
    fut = loop.create_future()

    def on_readable():
        if fut.done():
            return
        try:
            data, addr = sock.recvfrom(bufsize)
        except (BlockingIOError, InterruptedError):
            return
        except OSError as exc:
            fut.set_exception(exc)
            return
        fut.set_result((data, addr))

    loop.add_reader(sock.fileno(), on_readable)
    try:
        return await fut
    finally:
        try:
            loop.remove_reader(sock.fileno())
        except (OSError, ValueError):
            pass


async def peek_then_recv_probe(
    loop,
    sock,
    want_nonce,
    bufsize=2048,
):
    """Wait for inbound, peek at it, conditionally consume.

    Returns ((data, addr), True) when a *probe* (PROBE_MAGIC +
    matching nonce) is at the head of the queue and we've
    consumed it, OR (None, False) when something arrived but it
    wasn't a probe -- in that case the data is left in the
    kernel queue for the next consumer (the application's Pipe)
    so we don't eat real user data during the algorithm phase.

    This is the fix for "the algorithm consumes user data".  The
    cone side often converges first, returns from
    run_non_sym_side, the application immediately calls
    pipe.send().  The user's send arrives at the sym side before
    sym's watch loop has finished -- without MSG_PEEK, sym's
    recvfrom takes the user data off the queue, decode_probe
    returns None, sym's loop continues, the data is gone.
    """
    fut = loop.create_future()

    def on_readable():
        if fut.done():
            return
        try:
            # Peek -- do NOT consume.
            data, addr = sock.recvfrom(bufsize, socket.MSG_PEEK)
        except (BlockingIOError, InterruptedError):
            return
        except OSError as exc:
            fut.set_exception(exc)
            return
        fut.set_result((data, addr))

    loop.add_reader(sock.fileno(), on_readable)
    try:
        data, addr = await fut
    finally:
        try:
            loop.remove_reader(sock.fileno())
        except (OSError, ValueError):
            pass

    if decode_probe(data, want_nonce) is None:
        # Not a probe -- leave for the Pipe layer.
        return None, False
    # Probe -- consume it now.
    try:
        sock.recvfrom(bufsize)
    except (BlockingIOError, OSError):
        pass
    return (data, addr), True


# ─────────────────────────────────────────────────────────────────
# Cone side
# ─────────────────────────────────────────────────────────────────


def sync_run_non_sym_side(
    bind_ip,
    known_port,
    peer_ext_ip,
    nonce,
    probe_count=DEFAULT_PROBE_COUNT,
    listen_timeout=PROBE_LISTEN_TIMEOUT,
    rng=None,
    sock=None,
    own_ext_ip=None,
    interface=None,
    require_alignment=True,
):
    """Sync version of run_non_sym_side.

    No asyncio.add_reader / remove_reader cycling -- uses
    select() for the wait + plain recvfrom for delivery.  Run
    from a thread executor.  The sock is therefore *never*
    registered with the asyncio loop's selector during the
    algorithm phase, so when the plugin hands it to
    create_datagram_endpoint afterwards the transport's
    _read_ready installs cleanly and fires reliably on inbound.
    """
    import select as select_mod
    own_ext_ip = normalize_ip6(own_ext_ip) if own_ext_ip else own_ext_ip
    peer_ext_ip = normalize_ip6(peer_ext_ip)
    if sock is None:
        sock = make_udp_socket(bind_ip, known_port, interface=interface)
    sock.setblocking(False)

    actual_port = sock.getsockname()[1]
    print("[RP-NONSYM] start port={0} nonce={1}".format(
        actual_port, nonce.hex()[:8],
    ))

    ports = random_probe_ports(probe_count, rng=rng)
    expected_src_ports = set(ports)
    for idx, dst_port in enumerate(ports):
        try:
            sock.sendto(
                encode_probe(nonce, ROLE_CONE, idx),
                resolve_dest_tup(sock.family, peer_ext_ip, dst_port, socket.SOCK_DGRAM),
            )
        except OSError:
            continue

    print("[RP-NONSYM] fired {0} cone probes to {1}, listening".format(
        len(ports), peer_ext_ip,
    ))
    datagrams_seen = 0
    deadline = time.time() + listen_timeout
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            print("[RP-NONSYM] timeout after {0} datagrams".format(datagrams_seen))
            return None
        try:
            ready, _, _ = select_mod.select([sock], [], [], remaining)
        except (OSError, select_mod.error):
            return None
        if not ready:
            print("[RP-NONSYM] timeout after {0} datagrams".format(datagrams_seen))
            return None
        try:
            data, peer = sock.recvfrom(2048, socket.MSG_PEEK)
        except (BlockingIOError, InterruptedError):
            continue
        except ConnectionResetError:
            # WSAECONNRESET = ICMP port-unreachable from one of our cone probes.
            # On Windows, recvfrom(MSG_PEEK) does NOT consume the error --
            # the same error fires on every peek until a bare recvfrom drains it.
            # Drain it here so the next iteration can see real sym probes.
            try:
                sock.recvfrom(2048)
            except (OSError, BlockingIOError):
                pass
            continue
        except OSError:
            return None

        datagrams_seen += 1
        # Normalize v6 peer addr -- XP's stack returns garbage in
        # the flowinfo field (>2^20) which makes any subsequent
        # sendto / connect raise OverflowError. Mirrors the fix
        # in udp_punch_engine.watch_for_winner.
        if len(peer) == 4:
            scope_id = peer[3] if str(peer[0]).lower().startswith("fe80") else 0
            peer = (normalize_ip6(peer[0]), peer[1], 0, scope_id)

        # Probe-only consumption: non-probes stay in the queue
        # for the application Pipe.
        parsed = decode_probe(data, nonce)
        print("[RP-NONSYM] datagram from {0}:{1} len={2} decode={3}".format(
            peer[0], peer[1], len(data), parsed,
        ))
        if parsed is None:
            # Not our probe -- leave in the queue.  Yield via a
            # tiny sleep so we don't spin if there's persistent
            # non-probe data.
            time.sleep(0.02)
            continue
        # Consume the probe.
        try:
            sock.recvfrom(2048)
        except (BlockingIOError, OSError):
            continue
        if parsed["role"] != ROLE_SYM:
            print("[RP-NONSYM] skip: role={0} not SYM".format(parsed["role"]))
            continue
        if own_ext_ip and peer[0] == own_ext_ip:
            print("[RP-NONSYM] skip: peer IP == own_ext_ip {0}".format(own_ext_ip))
            continue
        if require_alignment and peer[1] not in expected_src_ports:
            print("[RP-NONSYM] skip: alignment check {0} not in expected".format(peer[1]))
            continue
        try:
            sock.sendto(
                encode_probe(nonce, ROLE_CONE, PROBE_IDX_CONFIRM),
                peer,
            )
        except OSError:
            pass
        print("[RP-NONSYM] converged (tentative): peer={0}:{1}".format(peer[0], peer[1]))
        # Phase 2: wait briefly for SYM_CONFIRM so that when there are
        # multiple birthday-paradox collisions both sides lock onto the
        # SAME socket.  SYM sends CONFIRM from its winning socket; if
        # that differs from our tentative peer we override here.
        final_peer = peer
        confirm_deadline = time.time() + 2.0
        while time.time() < confirm_deadline:
            conf_remaining = confirm_deadline - time.time()
            if conf_remaining <= 0:
                break
            try:
                conf_ready, _, _ = select_mod.select([sock], [], [], conf_remaining)
            except (OSError, select_mod.error):
                break
            if not conf_ready:
                break
            try:
                cdata, cpeer = sock.recvfrom(2048, socket.MSG_PEEK)
            except (BlockingIOError, InterruptedError):
                continue
            except ConnectionResetError:
                try:
                    sock.recvfrom(2048)
                except (OSError, BlockingIOError):
                    pass
                continue
            except OSError:
                break
            if len(cpeer) == 4:
                scope_id = cpeer[3] if str(cpeer[0]).lower().startswith("fe80") else 0
                cpeer = (normalize_ip6(cpeer[0]), cpeer[1], 0, scope_id)
            cparsed = decode_probe(cdata, nonce)
            if cparsed is None:
                time.sleep(0.02)
                continue
            try:
                sock.recvfrom(2048)
            except (BlockingIOError, OSError):
                continue
            if cparsed["role"] != ROLE_SYM:
                continue
            if own_ext_ip and cpeer[0] == own_ext_ip:
                continue
            if require_alignment and cpeer[1] not in expected_src_ports:
                continue
            if cparsed["idx"] != PROBE_IDX_CONFIRM:
                # Regular SYM probe (not the CONFIRM yet); send CONE_CONFIRM
                # back so SYM can still converge if it hasn't yet.
                try:
                    sock.sendto(
                        encode_probe(nonce, ROLE_CONE, PROBE_IDX_CONFIRM),
                        cpeer,
                    )
                except OSError:
                    pass
                continue
            # SYM_CONFIRM received: SYM has locked onto cpeer[1].
            if cpeer[1] != final_peer[1]:
                print("[RP-NONSYM] CONFIRM override: {0} -> {1}".format(
                    final_peer[1], cpeer[1],
                ))
                final_peer = cpeer
                try:
                    sock.sendto(
                        encode_probe(nonce, ROLE_CONE, PROBE_IDX_CONFIRM),
                        final_peer,
                    )
                except OSError:
                    pass
            break
        print("[RP-NONSYM] converged (final): peer={0}:{1}".format(
            final_peer[0], final_peer[1],
        ))
        return {"sock": sock, "peer": final_peer, "role": "non_sym"}


def sync_run_symmetric_side(
    bind_ip,
    cone_ext_ip,
    cone_ext_port,
    nonce,
    probe_count=DEFAULT_PROBE_COUNT,
    listen_timeout=PROBE_LISTEN_TIMEOUT,
    rng=None,
    interface=None,
):
    """Sync version of run_symmetric_side.

    Opens N sockets, each on a distinct local source port, fires
    one probe from each, then loops select() across all of them
    waiting for the first cone CONFIRM.
    """
    import select as select_mod
    cone_ext_ip = normalize_ip6(cone_ext_ip)
    src_ports = random_probe_ports(probe_count, rng=rng)
    socks = []
    for src_port in src_ports:
        try:
            socks.append(make_udp_socket(bind_ip, src_port, interface=interface))
        except OSError:
            continue
    if not socks:
        return None
    for s in socks:
        s.setblocking(False)
    print("[RP-SYM] start nonce={0} socks={1} target={2}:{3}".format(
        nonce.hex()[:8], len(socks), cone_ext_ip, cone_ext_port,
    ))
    probes_sent = 0
    for idx, s in enumerate(socks):
        try:
            s.sendto(
                encode_probe(nonce, ROLE_SYM, idx),
                resolve_dest_tup(s.family, cone_ext_ip, cone_ext_port, socket.SOCK_DGRAM),
            )
            probes_sent += 1
        except OSError:
            continue
    print("[RP-SYM] fired {0} sym probes, listening".format(probes_sent))

    deadline = time.time() + listen_timeout
    winner = None
    while time.time() < deadline:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        try:
            ready, _, _ = select_mod.select(socks, [], [], min(remaining, 1.0))
        except (OSError, select_mod.error):
            break
        if not ready:
            continue
        for s in ready:
            try:
                data, peer = s.recvfrom(2048, socket.MSG_PEEK)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                continue
            # Normalize v6 peer addr (XP flowinfo workaround).
            if len(peer) == 4:
                scope_id = peer[3] if str(peer[0]).lower().startswith("fe80") else 0
                peer = (normalize_ip6(peer[0]), peer[1], 0, scope_id)
            parsed = decode_probe(data, nonce)
            if parsed is None:
                # Non-probe -- leave for Pipe.  Don't drain this
                # sock; it might be the winner whose data is
                # being delivered concurrently with select.
                continue
            # Consume the probe.
            try:
                s.recvfrom(2048)
            except (BlockingIOError, OSError):
                continue
            if parsed["role"] != ROLE_CONE:
                continue
            if cone_ext_ip and peer[0] != cone_ext_ip:
                continue
            # Any cone probe (regular or CONFIRM) wins.  Send CONFIRM 3x
            # so NON_SYM's Phase 2 override window receives it reliably.
            for _ in range(3):
                try:
                    s.sendto(
                        encode_probe(nonce, ROLE_SYM, PROBE_IDX_CONFIRM),
                        peer,
                    )
                except OSError:
                    pass
            winner = {"sock": s, "peer": peer, "role": "sym"}
            break
        if winner is not None:
            break

    if winner is None:
        close_all(socks)
        return None

    # Close losers.
    for s in socks:
        if s is not winner["sock"]:
            try:
                s.close()
            except OSError:
                pass
    return winner


async def run_non_sym_side(
    bind_ip,
    known_port,
    peer_ext_ip,
    nonce,
    probe_count=DEFAULT_PROBE_COUNT,
    listen_timeout=PROBE_LISTEN_TIMEOUT,
    rng=None,
    sock=None,
    own_ext_ip=None,
    interface=None,
    require_alignment=True,
):
    """
    Run the non-symmetric half of the random-probe rendezvous.

    *sock* is an already-bound UDP socket -- the plugin pre-binds
    one before the signal exchange so the chosen source port can be
    advertised in the RandomProbeMsg as `known_port`, otherwise the
    symmetric peer fires 256 probes at port 0 and the round can
    never converge.  Pass *sock* to use the pre-bound one; if None,
    fall back to creating one via *bind_ip* + *known_port*.

    *interface* (when given) is forwarded to make_udp_socket so the
    fallback path also gets SO_BINDTODEVICE pinning -- without
    that, packets sourced from a non-default NIC's IP can still
    egress through the default route's NIC.

    Returns {"sock": socket, "peer": (ip, port), "role": "non_sym"}
    on a successful collision, or None on timeout.

    The caller is responsible for closing the returned socket when
    the resulting connection is no longer needed.
    """
    if hasattr(asyncio, "get_running_loop"):
        loop = asyncio.get_running_loop()
    else:
        loop = asyncio.get_event_loop()
    if sock is None:
        sock = make_udp_socket(bind_ip, known_port, interface=interface)

    # Fire N probes at random destination ports on the peer's ext IP.
    # We don't sleep between sends -- the symmetric NAT at the other
    # end either has a matching mapping installed by now (the timing
    # barrier handled that) or it doesn't.
    ports = random_probe_ports(probe_count, rng=rng)
    expected_src_ports = set(ports)
    for idx, dst_port in enumerate(ports):
        try:
            sock.sendto(
                encode_probe(nonce, ROLE_CONE, idx),
                resolve_dest_tup(sock.family, peer_ext_ip, dst_port, socket.SOCK_DGRAM),
            )
        except OSError:
            # ENETUNREACH / EHOSTUNREACH while firing -- skip and
            # keep going.  One bad probe doesn't fail the round.
            continue

    # Listen for the first inbound probe whose *source port* is one
    # we also fired at.  In real (cone, sym) NAT, that's the case
    # where the symmetric NAT will translate our reply on this
    # 4-tuple back to the same local sym socket -- the only useful
    # collisions.  Inbound from sym ext ports outside our dst set
    # represents non-aligned mappings the cone can't reliably
    # route a reply through, so we skip them.
    deadline = loop.time() + listen_timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            close_all([sock])
            return None
        try:
            result = await asyncio.wait_for(
                peek_then_recv_probe(loop, sock, nonce, 2048),
                timeout=remaining,
            )
        except asyncio.TimeoutError:
            close_all([sock])
            return None
        except OSError:
            close_all([sock])
            return None

        recvd, was_probe = result
        if not was_probe:
            # Real user data arrived (e.g. peer's pipe.send raced
            # ahead of our convergence return).  Leave it in the
            # kernel queue for the Pipe layer to deliver.  Yield
            # briefly so the kernel can wake another consumer.
            await asyncio.sleep(0.02)
            continue
        data, peer = recvd
        parsed = decode_probe(data, nonce)
        if parsed is None:
            continue
        # Reject probes from our own role -- they're either our
        # own hairpinned outbound (self-loop) or a stray.
        if parsed["role"] != ROLE_SYM:
            continue
        # Reject self-loops: an "aligned" probe whose source IP is
        # our own external IP isn't from the peer -- it's our own
        # outbound that got hairpinned back to us by something in
        # the path (router NAT loopback, asymmetric routing on a
        # multi-NIC host with default-gw imbalance, etc).
        # Replying here would just keep echoing into the loop, and
        # the actual peer never sees us.  Keep listening for a real
        # peer probe.
        if own_ext_ip and peer[0] == own_ext_ip:
            continue
        if require_alignment and peer[1] not in expected_src_ports:
            # Restrict-port NAT case: our home router only routes
            # inbound from peers we've previously sent to.  The
            # symmetric peer's NAT mapped this flow to an ext port
            # outside our dst set, so our home router didn't open
            # an inbound permission for it -- replying probably
            # won't land anywhere useful.  Keep listening for an
            # aligned probe whose source port is one we fired at.
            #
            # Skipped (require_alignment=False) when our NAT is
            # full-cone / open-internet: the home router routes
            # inbound from ANY external source on the mapped port,
            # so any sym probe reaches us and any reply we send
            # back travels through the carrier's per-flow mapping
            # to the right sym sock.  Filtering by alignment in
            # that case rejects 37%+ of legitimate convergences.
            continue
        # Aligned 4-tuple.  Send the CONFIRM probe so the symmetric
        # side's watcher locks onto *this* socket pair, not whichever
        # of its sockets happened to receive a regular cone probe
        # first.
        try:
            sock.sendto(
                encode_probe(nonce, ROLE_CONE, PROBE_IDX_CONFIRM),
                peer,
            )
        except OSError:
            pass
        return {"sock": sock, "peer": peer, "role": "non_sym"}


# ─────────────────────────────────────────────────────────────────
# Symmetric side
# ─────────────────────────────────────────────────────────────────


async def run_symmetric_side(
    bind_ip,
    cone_ext_ip,
    cone_ext_port,
    nonce,
    probe_count=DEFAULT_PROBE_COUNT,
    listen_timeout=PROBE_LISTEN_TIMEOUT,
    rng=None,
    interface=None,
):
    """
    Run the symmetric-side half of the random-probe rendezvous.

    Opens *probe_count* UDP sockets, each on a distinct local source
    port, fires one probe from each at (cone_ext_ip, cone_ext_port),
    then listens on all of them for the first cone reply.  Returns
    {"sock": winner, "peer": (ip, port), "role": "sym"} on success,
    or None on timeout.

    *interface* (when given) is forwarded to make_udp_socket so
    each socket gets SO_BINDTODEVICE pinning -- without this,
    packets from a non-default NIC's IP egress through the
    default-route NIC instead of the bound interface.

    All non-winning sockets are closed before the function returns.
    """
    if hasattr(asyncio, "get_running_loop"):
        loop = asyncio.get_running_loop()
    else:
        loop = asyncio.get_event_loop()
    src_ports = random_probe_ports(probe_count, rng=rng)

    socks = []
    for src_port in src_ports:
        try:
            socks.append(make_udp_socket(bind_ip, src_port, interface=interface))
        except OSError:
            # Port collision with another local listener -- skip.
            continue

    if not socks:
        return None

    # Fire one probe from every socket so each one burns a fresh
    # external mapping on the symmetric NAT.
    for idx, s in enumerate(socks):
        try:
            s.sendto(
                encode_probe(nonce, ROLE_SYM, idx),
                resolve_dest_tup(s.family, cone_ext_ip, cone_ext_port, socket.SOCK_DGRAM),
            )
        except OSError:
            continue

    # Race the receive on every socket.  As soon as *one* gets a
    # valid probe back we cancel the rest and return that socket
    # as the winner.
    deadline = loop.time() + listen_timeout

    async def watch(sock):
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return None
            try:
                result = await asyncio.wait_for(
                    peek_then_recv_probe(loop, sock, nonce, 2048),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                return None
            except OSError:
                return None

            recvd, was_probe = result
            if not was_probe:
                # Real user data arrived (cone converged faster
                # and the application immediately did pipe.send).
                # Leave it for the Pipe layer; another sym sock
                # may still see a CONFIRM.
                await asyncio.sleep(0.02)
                continue
            data, peer = recvd
            parsed = decode_probe(data, nonce)
            if parsed is None:
                continue
            # Reject probes from our own role (self-loop / stray).
            if parsed["role"] != ROLE_CONE:
                continue
            # Verify peer source IP matches the cone we agreed
            # on -- defends against a stray packet from a
            # different service triggering a false convergence
            # even if it happens to nonce-match.
            if cone_ext_ip and peer[0] != cone_ext_ip:
                continue
            # Accept *any* cone probe (regular or CONFIRM).  The
            # cone's regular probes prime our NAT mapping for
            # the inbound flow; treating them as a hit shortens
            # the round-trip + doubles the effective collision
            # rate (we no longer need to wait for the cone to
            # decide which sym source port is "aligned" -- we
            # send a CONFIRM-back ourselves and lock).  When the
            # cone DOES send a CONFIRM later, the dup is harmless
            # (PipeEvents filters probes via add_msg).
            try:
                sock.sendto(
                    encode_probe(nonce, ROLE_SYM, PROBE_IDX_CONFIRM),
                    peer,
                )
            except OSError:
                pass
            return {"sock": sock, "peer": peer, "role": "sym"}

    tasks = [asyncio.ensure_future(watch(s)) for s in socks]
    try:
        done, pending = await asyncio.wait(
            tasks, return_when=asyncio.FIRST_COMPLETED
        )
    except asyncio.CancelledError:
        for t in tasks:
            t.cancel()
        close_all(socks)
        raise

    winner = None
    for t in done:
        try:
            res = t.result()
        except (asyncio.CancelledError, OSError):
            res = None
        if res is not None and winner is None:
            winner = res

    for t in pending:
        t.cancel()

    if winner is None:
        close_all(socks)
        return None

    # Reply on the same 4-tuple so the cone sees an inbound too
    # (it already received an earlier probe from us, but a fresh
    # one over the now-locked 4-tuple confirms the channel is
    # fully bidirectional from sym -> cone).
    try:
        winner["sock"].sendto(
            encode_probe(nonce, ROLE_SYM, PROBE_IDX_CONFIRM),
            winner["peer"],
        )
    except OSError:
        pass

    # Close all losers.
    for s in socks:
        if s is not winner["sock"]:
            try:
                s.close()
            except OSError:
                pass
    return winner


# ─────────────────────────────────────────────────────────────────
# Bidirectional spray: direction-agnostic NAT punch
# ─────────────────────────────────────────────────────────────────


def sync_run_bidirectional_spray(
    bind_ip,
    peer_ext_ip,
    nonce,
    probe_count=DEFAULT_PROBE_COUNT,
    listen_timeout=PROBE_LISTEN_TIMEOUT,
    rng=None,
    interface=None,
    own_ext_ip=None,
):
    """Direction-agnostic random-probe punch: both sides run this same
    code regardless of which is initiator/responder or what NAT type
    detection said.

    Algorithm: open `probe_count` UDP sockets on random local source
    ports, fire one probe from each to a random destination port on
    `peer_ext_ip`, then `select()` across all sockets for the first
    incoming probe carrying the matching nonce.

    Why this works for any NAT pair:
      - Each fired probe creates an outbound NAT mapping for that
        (local_src_port, peer_ext_ip, peer_dst_port) tuple.
      - For a peer probe to land here, the peer must dst-match an
        outbound mapping we have open. Since we hold `probe_count`
        mappings (one per local socket) and the peer fires
        `probe_count` probes at random destination ports, the
        expected number of collisions is roughly
        `probe_count^2 / 65000` -- with 256 each side that's ~1.
      - No assumption about NAT type on either end. Symmetric NAT
        (mobile carriers), full-cone, address-restricted, port-
        restricted -- all work the same way: enough mappings open
        on each side that some random probe pair lines up.

    Trade-off vs the asymmetric algorithm: gives up the optimisation
    where one side can use a single known port; uses 256 sockets on
    both sides instead of 256+1. Bandwidth is the same (256 probes
    each direction). Direction asymmetry is gone, which is what we
    want for the matrix where NAT-type detection is unreliable.

    Returns {"sock": winning_socket, "peer": (ip,port), "role": "spray"}
    on success, or None on timeout. Caller closes the returned sock.
    """
    import select as select_mod
    peer_ext_ip = normalize_ip6(peer_ext_ip)

    # Master/slave election by IP comparison: same symmetry-breaker
    # tcp_punch's choose_winning_tcp_sock uses (`our_ip > their_ip`).
    # Both sides compute the same winner without coordination because
    # the math is symmetric -- but ONLY if both sides compare the
    # same pair of IPs.  bind_ip on a NAT'd host is the LAN-side
    # address which the peer never sees, so comparing bind_ips would
    # give an inconsistent answer when one side is behind NAT.  The
    # external IP (what the peer actually observes) is the right
    # quantity; tcp_punch passes route.ext() as decider_ip for the
    # same reason.  Caller is responsible for passing own_ext_ip;
    # falls back to bind_ip when own_ext_ip is unset (e.g. LAN-only
    # callers that haven't done STUN).  This fallback works as long
    # as both sides are NOT behind NAT (then bind_ip == ext_ip);
    # mixing a NAT'd and non-NAT'd peer needs own_ext_ip to be
    # populated.
    own_ip_for_election = normalize_ip6(own_ext_ip) if own_ext_ip else normalize_ip6(bind_ip)
    is_master = own_ip_for_election > peer_ext_ip

    src_ports = random_probe_ports(probe_count, rng=rng)
    dst_ports = random_probe_ports(probe_count, rng=rng)
    socks = []
    for sp in src_ports:
        try:
            socks.append(make_udp_socket(bind_ip, sp, interface=interface))
        except OSError:
            continue
    if not socks:
        return None
    for s in socks:
        s.setblocking(False)

    print("[RP-SPRAY] start nonce={0} socks={1} target_ip={2} role={3}".format(
        nonce.hex()[:8], len(socks), peer_ext_ip,
        "MASTER" if is_master else "SLAVE",
    ))

    # Fire one probe from each socket to a random destination port.
    # Use ROLE_SYM as the marker; the receive side accepts any role
    # so long as the nonce matches, so it doesn't matter which label
    # we send -- we keep ROLE_SYM purely for backward-compatibility
    # with peers still running the old asymmetric NON_SYM code path
    # (they look for ROLE_SYM and will still treat us as the sym
    # peer they expect).
    probes_sent = 0
    for s, dp in zip(socks, dst_ports):
        try:
            s.sendto(
                encode_probe(nonce, ROLE_SYM, probes_sent),
                resolve_dest_tup(s.family, peer_ext_ip, dp, socket.SOCK_DGRAM),
            )
            probes_sent += 1
        except OSError:
            continue
    print("[RP-SPRAY] fired {0} probes, listening".format(probes_sent))

    # Convergence protocol (master/slave, modelled on tcp_punch):
    #
    #   master: locks on the FIRST matching frame to land (PROBE or
    #     CONFIRM) on any of its sockets, then sends a 5x CONFIRM
    #     burst from THAT socket back to peer.  The burst is the
    #     "I picked this path" marker the slave is waiting for; the
    #     redundancy hides single-packet loss on the return leg.
    #
    #   slave: refuses to lock on PROBEs (those races each side's
    #     independent first-arrival, which is what broke the previous
    #     algorithm).  Reflects a CONFIRM back on each PROBE arrival
    #     so the master has paths to choose from and so master's NAT
    #     pinhole stays warm, but only commits to a socket once a
    #     CONFIRM arrives -- by construction that CONFIRM came from
    #     master AFTER master picked, so both sides agree on the path.
    deadline = time.time() + listen_timeout
    winner = None
    datagrams_seen = 0
    parsed_ok = 0
    parsed_fail = 0
    peer_ip_mismatch = 0
    while time.time() < deadline:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        try:
            ready, _, _ = select_mod.select(socks, [], [], min(remaining, 1.0))
        except (OSError, select_mod.error):
            break
        if not ready:
            continue
        for s in ready:
            try:
                data, peer = s.recvfrom(2048, socket.MSG_PEEK)
            except ConnectionResetError:
                # WSAECONNRESET = ICMP port-unreachable from one of our probes.
                # MSG_PEEK does not consume the error on Windows -- every peek
                # fires again until a bare recvfrom drains it.
                try:
                    s.recvfrom(2048)
                except (OSError, BlockingIOError):
                    pass
                continue
            except (BlockingIOError, InterruptedError, OSError):
                continue
            # Normalize v6 peer addr (XP flowinfo workaround).
            if len(peer) == 4:
                scope_id = peer[3] if str(peer[0]).lower().startswith("fe80") else 0
                peer = (normalize_ip6(peer[0]), peer[1], 0, scope_id)
            datagrams_seen += 1
            parsed = decode_probe(data, nonce)
            print("[RP-SPRAY-RX] dgram#{0} from {1}:{2} len={3} parsed={4} my_sock_port={5}".format(
                datagrams_seen, peer[0], peer[1], len(data),
                "ok" if parsed is not None else "no",
                s.getsockname()[1] if s.getsockname() else -1,
            ))
            if parsed is None:
                parsed_fail += 1
                # Non-probe -- leave for Pipe; could be early data.
                # Sleep briefly so the same datagram at head of queue
                # does not spin select() at full speed.
                time.sleep(0.001)
                continue
            parsed_ok += 1
            # Consume the probe.
            try:
                s.recvfrom(2048)
            except (BlockingIOError, OSError):
                continue
            if peer_ext_ip and peer[0] != peer_ext_ip:
                peer_ip_mismatch += 1
                print("[RP-SPRAY-RX] skip: peer_ip {0} != expected {1}".format(
                    peer[0], peer_ext_ip,
                ))
                continue

            is_confirm = parsed["idx"] == PROBE_IDX_CONFIRM

            if is_master:
                # Master commits on first arrival.  Send a CONFIRM
                # burst from this socket so the slave's listener
                # picks up the marker even under packet loss; then
                # break out and let the caller wrap this socket.
                for _ in range(5):
                    try:
                        s.sendto(
                            encode_probe(nonce, ROLE_SYM, PROBE_IDX_CONFIRM),
                            peer,
                        )
                    except OSError:
                        pass
                winner = {"sock": s, "peer": peer, "role": "spray-master"}
                break

            # Slave path: only CONFIRMs lock us in.  A plain PROBE
            # gets a CONFIRM-back so master's NAT pinhole on this
            # 4-tuple stays warm and master has at least one path
            # to choose from.
            if is_confirm:
                winner = {"sock": s, "peer": peer, "role": "spray-slave"}
                break
            for _ in range(2):
                try:
                    s.sendto(
                        encode_probe(nonce, ROLE_SYM, PROBE_IDX_CONFIRM),
                        peer,
                    )
                except OSError:
                    pass
        if winner is not None:
            break

    if winner is None:
        print("[RP-SPRAY] timeout: dgrams_seen={0} parsed_ok={1} parsed_fail={2} peer_ip_mismatch={3}".format(
            datagrams_seen, parsed_ok, parsed_fail, peer_ip_mismatch,
        ))
        close_all(socks)
        return None

    # Close losers.
    for s in socks:
        if s is not winner["sock"]:
            try:
                s.close()
            except OSError:
                pass
    print("[RP-SPRAY] converged peer={0}:{1} role={2} dgrams_seen={3} parsed_ok={4}".format(
        winner["peer"][0], winner["peer"][1], winner["role"],
        datagrams_seen, parsed_ok,
    ))
    return winner


# ─────────────────────────────────────────────────────────────────
# Coordination: wait until the shared rendezvous time
# ─────────────────────────────────────────────────────────────────


async def wait_until(unix_time, max_sleep=30.0):
    """
    Sleep until the given unix timestamp.

    Bounded by *max_sleep* so a misbehaving signal channel can't
    stall a plugin run forever.  No-ops when the rendezvous is in
    the past (the caller already missed the window; the algorithm
    will fire late, which is usually fine on UDP because the NAT
    mappings hang around for tens of seconds).
    """
    delay = unix_time - int(time.time())
    if delay <= 0:
        return
    if delay > max_sleep:
        delay = max_sleep
    await asyncio.sleep(delay)
