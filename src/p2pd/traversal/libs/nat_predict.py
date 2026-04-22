"""NAT port-prediction algorithms used by hole-punching."""
from typing import Any, Dict, List, Optional, Tuple
from aionetiface import *

MAX_PREDICT_NO = 100

# Duplicate defs
# TODO: should this module be moved into nat lib? probably.
TCP_PUNCH_LAN = 1
TCP_PUNCH_REMOTE = 2
TCP_PUNCH_SELF = 3


class NATMapping:
    """Represents a single NAT port mapping with local, reply, and remote ports."""

    def __init__(self, mapping: List[Any], sock: Optional[Any] = None) -> None:
        self.local = mapping[0]
        self.reply = mapping[1]
        self.remote = mapping[2]
        self.sock = sock

    def __str__(self) -> str:
        buf = fstr(
            "{0} {1} ",
            (
                self.local,
                self.reply,
            ),
        )
        buf += fstr(
            "{0} {1}",
            (
                self.remote,
                self.sock,
            ),
        )
        return buf

    def to_json(self) -> List[Any]:
        """Return the mapping as a JSON-serialisable [local, reply, remote] list."""
        return [self.local, self.reply, self.remote]

    def to_dict(self) -> Dict[str, Any]:
        """Serialise this mapping to a dictionary with local, reply, remote, and sock fields."""
        return {
            "local": self.local,
            "reply": self.reply,
            "remote": self.remote,
            "sock": self.sock,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "NATMapping":
        """Reconstruct a NATMapping from a serialised dictionary."""
        return NATMapping([d["local"], d["reply"], d["remote"]], d["sock"])


def mappings_dicts_to_objs(mappings: List[Dict[str, Any]]) -> List[NATMapping]:
    """Convert a list of mapping dicts to NATMapping objects."""
    ret = []
    for d in mappings:
        ret.append(NATMapping.from_dict(d))

    return ret


def mappings_objs_to_dicts(mappings: List[NATMapping]) -> List[Dict[str, Any]]:
    """Convert a list of NATMapping objects to serialisable dicts."""
    ret = []
    for m in mappings:
        ret.append(m.to_dict())

    return ret


async def get_high_port_mapping(stun_client: Any) -> "NATMapping":
    """Bind to a high-numbered port via STUN and return the resulting NAT mapping."""
    assert stun_client.conf["reuse_addr"]
    nic = stun_client.interface
    af = stun_client.af
    for _ in range(0, 5):
        try:
            # Reserve a sock for use.
            _, high_port = await get_high_port_socket(
                nic.route(af),
                socket_factory,
                sock_type=TCP,
            )

            # Bind to a sock with that port.
            route = nic.route(af)
            await route.bind(port=high_port)

            # Determine associated remote port.
            ret = await stun_client.get_mapping(
                # Upgraded to a pipe.
                pipe=route
            )

            return NATMapping([ret[0], 0, ret[1]], ret[2])
        except (OSError, asyncio.TimeoutError):
            log_exception()
            continue

    raise ConnectionError("high port sock fail.")


def get_mapping_templates(use_stun_port: bool = False, use_range: List[int] = [2000, MAX_PORT], test_no: int = 2) -> List[NATMapping]:
    """Build placeholder NATMapping templates used when no peer mappings are yet available."""
    mappings = []
    for _ in range(0, test_no):
        # Default port for when there is a
        # [port restrict, rand delta] NAT.
        if use_stun_port:
            mappings.append(NATMapping([0, 0, STUN_PORT]))
            break
        else:
            mappings.append(NATMapping([0, 0, from_range(use_range)]))

    return mappings


def init_predictions(mode: int, src_nat: Dict[str, Any], dest_nat: Dict[str, Any], recv_mappings: Optional[List[NATMapping]] = None, test_no: int = 2) -> Tuple[List[int], Dict[str, Any], Dict[str, Any], List[NATMapping]]:
    """Normalise NAT info and produce initial mapping templates for the prediction algorithm."""
    # Set test_no based on recipients test no.
    # [[remote port, required reply port], ...]
    if recv_mappings is not None:
        test_no = len(recv_mappings)

    # Patch NAT if it's not remote.
    if mode in [TCP_PUNCH_LAN, TCP_PUNCH_SELF]:
        src_nat = nat_info(OPEN_INTERNET, delta_info(NA_DELTA, 0))

        dest_nat = nat_info(OPEN_INTERNET, delta_info(NA_DELTA, 0))

    # Attempt to make chosen local ports compatible
    # with any reply port restrictions.
    use_stun_port = nats_can_predict(src_nat, dest_nat)
    use_range = nats_intersect(src_nat, dest_nat, test_no)
    if use_stun_port:
        test_no = 1

    # Pretend we have a list of mappings from a peer
    # even if we don't -- used to simplify code.
    if recv_mappings is None:
        recv_mappings = get_mapping_templates(
            use_stun_port,
            use_range,
            test_no,
        )

    return use_range, src_nat, dest_nat, recv_mappings


async def preload_mappings(no: int, stuns: List[Any]) -> List[NATMapping]:
    """Concurrently fetch no high-port STUN mappings from the given STUN clients."""
    # Get a mapping to use.
    tasks = []
    for _ in range(0, no):
        stun = random.choice(stuns)
        task = get_high_port_mapping(stun)
        tasks.append(task)

    mappings = await asyncio.gather(*tasks)
    mappings = strip_none(mappings)
    return mappings


def get_single_mapping(
mode: int,
    rmap: NATMapping,
    last_mapped: NATMapping,
    use_range: List[int],
    our_nat: Dict[str, Any],
    preloaded_mapping: NATMapping,
    step: int = 1000,
) -> "NATMapping":
    """Predict a single outbound NAT mapping that coordinates with the peer's rmap."""
    # Allow last mapped to be modified from inside func.
    last_local = last_mapped.local
    last_remote = last_mapped.remote

    # Need to bind to a specific port.
    remote_port = rmap.remote
    reply_port = rmap.reply
    bind_port = reply_port or remote_port
    assert bind_port
    assert remote_port

    # Normally the code tries to use the same port as the recipient to simplify
    # coordination. But when punching yourself, the same local port is already
    # in use, so we must choose a non-conflicting port instead.
    if mode == TCP_PUNCH_SELF:
        remote = field_wrap(remote_port + step, [2001, MAX_PORT])

        return NATMapping(
            [
                remote,
                0,
                remote,
            ]
        )

    # If we're port restricted specify we're happy to use their mapping.
    # This may not be possible if our delta is random though.
    our_reply = bind_port if our_nat["type"] == RESTRICT_PORT_NAT else 0

    # Use their mapping as-is.
    if our_nat["is_open"]:
        return NATMapping([bind_port, 0, bind_port])

    # If preserving try use their mapping.
    if our_nat["delta"]["type"] == EQUAL_DELTA:
        if not in_range(bind_port, our_nat["range"]):
            bind_port = from_range(use_range)

        return NATMapping([bind_port, 0, bind_port])

    # NAT preserves distance between local ports in remote ports.
    if our_nat["delta"]["type"] == PRESERV_DELTA:
        # Try use their port but make sure it fits in our range.
        if not in_range(bind_port, our_nat["range"]):
            bind_port = from_range(use_range)

        # How far away is our last mapping from desired port.
        # Delta dist will wrap inside any assumed range.
        dist = abs(n_dist(last_remote, bind_port))
        next_local = port_wrap(last_local + dist)

        # Return results.
        return NATMapping([next_local, our_reply, bind_port])

    # Independent and dependent NATs allocate mappings from a known range
    # (measured via a large number of STUN tests) and wrap around when they
    # reach the end. Imprecise ranges cause wrong wrap-around predictions and
    # failed hole punching. Ranges must be exact for these delta types;
    # increasing test_no and rounding to powers of two improves accuracy.

    # Poor concurrency support.
    if our_nat["delta"]["type"] == INDEPENDENT_DELTA:
        # We can use anything for a local port.
        # The remote mappings have a pattern regardless of local tuples.
        next_local = from_range([2000, MAX_PORT])
        next_remote = field_wrap(last_remote + our_nat["delta"]["value"], use_range)

        # Return port predictions.
        # These allocations apply even if strict port NAT.
        # But we tell other side to use a specific mapping for coordination.
        return NATMapping([next_local, our_reply, next_remote])

    # Poor concurrency support.
    if our_nat["delta"]["type"] == DEPENDENT_DELTA:
        next_local = port_wrap(last_local + 1)
        next_remote = field_wrap(last_remote + our_nat["delta"]["value"], use_range)

        # Return port predictions.
        # These allocations apply even if strict port NAT.
        # But we tell other side to use a specific mapping for coordination.
        return NATMapping([next_local, our_reply, next_remote])

    # Delta type is random -- get a mapping from STUN to reuse.
    # If we're port restricted then set our reply port to the STUN port.
    if our_nat["type"] in PREDICTABLE_NATS:
        # Calculate reply port.
        our_reply = 3478 if our_nat["type"] == RESTRICT_PORT_NAT else 0
        # TODO: Could connect to STUN port in their range.

        # Return results.
        return NATMapping(
            [preloaded_mapping.local, our_reply, preloaded_mapping.remote]
        )

    # Symmetric NATs only allow mappings per (src_ip, src_port, dest_ip,
    # dest_port). The only way to support them is if they also have a
    # non-random delta. Reaching this point means a random-delta symmetric
    # NAT — unpredictable and unsupported.
    raise AssertionError("Can't predict this NAT type.")


async def nat_prediction(mode: int, src_nat: Dict[str, Any], dest_nat: Dict[str, Any], stuns: List[Any], recv_mappings: Optional[List[NATMapping]] = None, test_no: int = 2) -> Tuple[List[NATMapping], List[NATMapping]]:
    """Compute predicted send and preloaded mappings for a hole-punch session."""
    # Setup nats and initial mapping templates.
    # The mappings will be filled in with details.
    use_range, src_nat, dest_nat, recv_mappings = init_predictions(
        mode, src_nat, dest_nat, recv_mappings, test_no
    )

    # Preload nat predictions then
    # mock single mapping can be a function.
    preloaded_mappings = await preload_mappings(len(recv_mappings), stuns)
    assert len(preloaded_mappings)

    # Use default ports for client if unknown
    # or try use their ports if known.
    results = []
    for i in range(0, len(recv_mappings)):
        # Default to using first mapped.
        try:
            preloaded_mapping = preloaded_mappings[i]
        except IndexError:
            preloaded_mapping = preloaded_mappings[0]

        # Predict our mappings.
        # Try to match our ports to any provided mappings.
        result = get_single_mapping(
            # Punching mode.
            mode,
            # Try match this mapping.
            recv_mappings[i],
            # A mapping fetch from STUN.
            # Only set depending on certain NATs.
            preloaded_mappings[-1],
            # Uses a range compatible with both NATs
            # Otherwise uses our range.
            use_range,
            # Info on our NAT type and delta.
            src_nat,
            # Get a result instantly.
            preloaded_mapping,
        )

        # Save prediction.
        results.append(result)

    return results, preloaded_mappings


def self_punch_patch(mode: int, mappings: List[NATMapping], step: int = 1000) -> None:
    """Offset local ports by step when punching to ourself to avoid port collisions."""
    if mode != TCP_PUNCH_SELF:
        return

    for m in mappings:
        m.local = port_wrap(m.local + step)
        m.remote = m.local


def update_for_reply_ports(
mode: int,
    src_nat: Dict[str, Any],
    dest_nat: Dict[str, Any],
    preloaded_mappings: List[NATMapping],
    send_mappings: List[NATMapping],
    recv_mappings: List[NATMapping],
) -> List[NATMapping]:
    """Adjust our local port predictions to satisfy the peer's reply port restrictions."""
    test_no = min(len(send_mappings), len(recv_mappings))
    use_range = nats_intersect(src_nat, dest_nat, test_no)
    bad_delta = [INDEPENDENT_DELTA, DEPENDENT_DELTA, RANDOM_DELTA]

    # Update our local ports for port restricted NATs.
    for i in range(0, test_no):
        # No NAT so reply ports don't apply.
        if mode == TCP_PUNCH_SELF:
            break

        # The update is to satisfy a port restricted NAT.
        # These NATs require a specific reply port.
        if not recv_mappings[i].reply:
            continue

        # We can satisfy their requirements.
        if src_nat["delta"]["type"] in bad_delta:
            continue

        # local, remote, reply, sock.
        mapping = get_single_mapping(
            mode,
            recv_mappings[i],
            preloaded_mappings[-1],
            use_range,
            src_nat,
            preloaded_mappings[i],
        )

        # Update our local port.
        send_mappings[i].local = mapping.local
        send_mappings[i].remote = recv_mappings[i].reply

    return send_mappings
