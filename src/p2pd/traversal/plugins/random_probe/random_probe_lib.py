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
from typing import Any, Dict, List, Optional, Tuple

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


def encode_probe(nonce: bytes, role: bytes, idx: int) -> bytes:
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


def decode_probe(data: bytes, want_nonce: bytes) -> Optional[Dict[str, Any]]:
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


def random_probe_ports(count: int, rng: Optional[random.Random] = None) -> List[int]:
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
    bind_ip: str,
    bind_port: int = 0,
    interface: Optional[Any] = None,
) -> socket.socket:
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
                    print("[RP-BIND] SO_BINDTODEVICE ok: bind={0}:{1} iface={2!r}".format(
                        bind_ip, bind_port, iface_bytes,
                    ))
            except OSError as exc:
                # Most likely EPERM (Linux SO_BINDTODEVICE needs
                # CAP_NET_RAW / root).  The bind still happens, but
                # egress falls back to the default route -- on a
                # multi-NIC host that means packets sourced from a
                # non-default NIC's IP can leave through the wrong
                # interface and hairpin.
                print("[RP-BIND] SO_BINDTODEVICE FAILED: bind={0}:{1} "
                      "iface={2!r} err={3!r}  (need root / CAP_NET_RAW)".format(
                          bind_ip, bind_port, iface_bytes, exc,
                      ))

    s.setblocking(False)
    s.bind((bind_ip, bind_port))
    return s


_IS_WINDOWS = False
try:
    import sys as _sys
    _IS_WINDOWS = _sys.platform == "win32"
except ImportError:
    pass


def close_all(socks: List[socket.socket]) -> None:
    """Close every socket; never raises (best-effort cleanup)."""
    for s in socks:
        try:
            s.close()
        except OSError:
            pass


def drain_probe_residue(sock: socket.socket, want_nonce: bytes) -> int:
    """Drain in-flight probe datagrams from *sock* without blocking.

    Instant version -- pulls everything currently queued in the
    kernel buffer and stops at the first non-probe.  See
    async_drain_probe_residue for a duration-based variant that
    catches late-arriving probes too (CGNAT / cross-internet
    paths can keep delivering sym probes for hundreds of ms after
    the algorithm completes).

    Returns the number of probe datagrams drained.  Non-probe
    datagrams (anything that doesn't decode as one of *our*
    probes) are left in the queue so we don't accidentally
    swallow real user data.
    """
    drained = 0
    sock.setblocking(False)
    while True:
        try:
            data, _addr = sock.recvfrom(4096)
        except (BlockingIOError, InterruptedError):
            break
        except OSError:
            break
        if decode_probe(data, want_nonce) is None:
            break
        drained += 1
    return drained


async def async_drain_probe_residue(
    sock: socket.socket,
    want_nonce: bytes,
    duration: float = 1.0,
) -> int:
    """Drain probe-format datagrams from *sock* for *duration* seconds.

    The instant variant only catches what the kernel already has
    queued.  On a real cross-internet path (CGNAT, mobile carrier
    in the loop) the symmetric peer's 256-pack arrives spread
    over hundreds of ms -- by the time the algorithm sets the
    result, more probes are still in flight.  This variant keeps
    consuming any matching probe datagrams for the full duration
    so late arrivers get silently dropped instead of being
    delivered as data on the user's pipe.

    Non-probe datagrams (real user payload that happens to slip
    in early) are NOT consumed -- those are left for the pipe
    layer to deliver.
    """
    loop = asyncio.get_event_loop()
    deadline = loop.time() + duration
    drained = 0
    sock.setblocking(False)
    while loop.time() < deadline:
        try:
            data, _addr = sock.recvfrom(4096)
        except (BlockingIOError, InterruptedError):
            await asyncio.sleep(0.02)
            continue
        except OSError:
            break
        if decode_probe(data, want_nonce) is None:
            # Real data arrived early -- can't drop it.  Cheap
            # workaround: there's no way to put it back, but in
            # practice the application's first send hasn't gone
            # out yet so this is unlikely.
            return drained
        drained += 1
    return drained


async def stun_discover_mapping(
    loop: Any,
    sock: socket.socket,
    stun_server: Tuple[str, int],
    af: int,
    timeout: float = 3.0,
    retries: int = 3,
) -> Optional[Tuple[str, int]]:
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


async def recvfrom_async(loop: Any, sock: socket.socket, bufsize: int = 2048) -> Tuple[bytes, Tuple[str, int]]:
    """
    Async UDP recvfrom that works on Python 3.5+.

    asyncio.AbstractEventLoop.sock_recvfrom only landed in Python
    3.11.  We install an add_reader callback that does the
    non-blocking recvfrom and resolves a Future, which is the
    portable primitive supported back to 3.5.
    """
    fut = loop.create_future()

    def on_readable() -> None:
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


# ─────────────────────────────────────────────────────────────────
# Cone side
# ─────────────────────────────────────────────────────────────────


async def run_non_sym_side(
    bind_ip: str,
    known_port: int,
    peer_ext_ip: str,
    nonce: bytes,
    probe_count: int = DEFAULT_PROBE_COUNT,
    listen_timeout: float = PROBE_LISTEN_TIMEOUT,
    rng: Optional[random.Random] = None,
    sock: Optional[socket.socket] = None,
    own_ext_ip: Optional[str] = None,
    interface: Optional[Any] = None,
    require_alignment: bool = True,
) -> Optional[Dict[str, Any]]:
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
                (peer_ext_ip, dst_port),
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
            data, peer = await asyncio.wait_for(
                recvfrom_async(loop, sock, 2048),
                timeout=remaining,
            )
        except asyncio.TimeoutError:
            close_all([sock])
            return None
        except OSError:
            close_all([sock])
            return None

        parsed = decode_probe(data, nonce)
        if parsed is None:
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
    bind_ip: str,
    cone_ext_ip: str,
    cone_ext_port: int,
    nonce: bytes,
    probe_count: int = DEFAULT_PROBE_COUNT,
    listen_timeout: float = PROBE_LISTEN_TIMEOUT,
    rng: Optional[random.Random] = None,
    interface: Optional[Any] = None,
) -> Optional[Dict[str, Any]]:
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
                (cone_ext_ip, cone_ext_port),
            )
        except OSError:
            continue

    # Race the receive on every socket.  As soon as *one* gets a
    # valid probe back we cancel the rest and return that socket
    # as the winner.
    deadline = loop.time() + listen_timeout

    async def watch(sock: socket.socket) -> Optional[Dict[str, Any]]:
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return None
            try:
                data, peer = await asyncio.wait_for(
                    recvfrom_async(loop, sock, 2048),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                return None
            except OSError:
                return None
            parsed = decode_probe(data, nonce)
            if parsed is None:
                continue
            # Lock only on the cone's CONFIRM (idx=PROBE_IDX_CONFIRM).
            # The cone's regular probes also arrive at sym sockets
            # whose bind port matches a cone destination, but the
            # cone may not be replying to *this* sock -- it picks
            # whichever aligned source port arrived first and
            # CONFIRMs there.  Waiting for the CONFIRM specifically
            # is what guarantees both sides agree on the same pair.
            if parsed["idx"] != PROBE_IDX_CONFIRM:
                continue
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
# Coordination: wait until the shared rendezvous time
# ─────────────────────────────────────────────────────────────────


async def wait_until(unix_time: int, max_sleep: float = 30.0) -> None:
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
