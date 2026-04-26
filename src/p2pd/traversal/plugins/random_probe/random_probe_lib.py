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


def make_udp_socket(bind_ip: str, bind_port: int = 0) -> socket.socket:
    """
    Create a non-blocking UDP socket bound to (bind_ip, bind_port).

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
    s.setblocking(False)
    s.bind((bind_ip, bind_port))
    return s


def close_all(socks: List[socket.socket]) -> None:
    """Close every socket; never raises (best-effort cleanup)."""
    for s in socks:
        try:
            s.close()
        except OSError:
            pass


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
) -> Optional[Dict[str, Any]]:
    """
    Run the non-symmetric half of the random-probe rendezvous.

    *sock* is an already-bound UDP socket -- the plugin pre-binds
    one before the signal exchange so the chosen source port can be
    advertised in the RandomProbeMsg as `known_port`, otherwise the
    symmetric peer fires 256 probes at port 0 and the round can
    never converge.  Pass *sock* to use the pre-bound one; if None,
    fall back to creating one via *bind_ip* + *known_port*.

    Returns {"sock": socket, "peer": (ip, port), "role": "non_sym"}
    on a successful collision, or None on timeout.

    The caller is responsible for closing the returned socket when
    the resulting connection is no longer needed.
    """
    loop = asyncio.get_event_loop()
    if sock is None:
        sock = make_udp_socket(bind_ip, known_port)

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
        if peer[1] not in expected_src_ports:
            # Symmetric peer's NAT mapped this flow to an ext port
            # outside our dst set -- replying here probably won't
            # land anywhere useful.  Keep listening for an aligned
            # one.
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
) -> Optional[Dict[str, Any]]:
    """
    Run the symmetric-side half of the random-probe rendezvous.

    Opens *probe_count* UDP sockets, each on a distinct local source
    port, fires one probe from each at (cone_ext_ip, cone_ext_port),
    then listens on all of them for the first cone reply.  Returns
    {"sock": winner, "peer": (ip, port), "role": "sym"} on success,
    or None on timeout.

    All non-winning sockets are closed before the function returns.
    """
    loop = asyncio.get_event_loop()
    src_ports = random_probe_ports(probe_count, rng=rng)

    socks = []
    for src_port in src_ports:
        try:
            socks.append(make_udp_socket(bind_ip, src_port))
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
