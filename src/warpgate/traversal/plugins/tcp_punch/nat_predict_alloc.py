"""NAT-prediction-based port allocator."""
import asyncio
import copy
from aionetiface import Interface, fstr, get_n_stun_clients, log, UDP
from .nat_predict import (
    NATMapping,
    nat_prediction,
    self_punch_patch,
    update_for_reply_ports,
    nat_info,
    RESTRICT_PORT_NAT,
    delta_info,
    EQUAL_DELTA,
    PRESERV_DELTA,
    INDEPENDENT_DELTA,
    DEPENDENT_DELTA,
    PREDICTABLE_NATS,
)


def is_predictable_nat(nat):
    """True if `get_single_mapping` can compute a port mapping for this NAT info.

    Predictability needs at least one of:
      - the NAT is open (no NAT, or symmetric UDP firewall)
      - the delta type is EQUAL / PRESERV / INDEPENDENT / DEPENDENT
      - the NAT type is in PREDICTABLE_NATS

    Reaching get_single_mapping's final ``raise`` means none of the above
    holds -- a symmetric NAT with random delta, the only shape we can't
    punch through.
    """
    if not isinstance(nat, dict):
        return False
    if nat.get("is_open"):
        return True
    delta = nat.get("delta") or {}
    if delta.get("type") in (
        EQUAL_DELTA, PRESERV_DELTA, INDEPENDENT_DELTA, DEPENDENT_DELTA,
    ):
        return True
    if nat.get("type") in PREDICTABLE_NATS:
        return True
    return False
from .punch_utils import get_punch_mode
from .punch_defs import (
    PortAlloc,
    INITIATED_PREDICTIONS,
    RECEIVED_PREDICTIONS,
    UPDATED_PREDICTIONS,
    INITIATOR,
    RECIPIENT,
    PUNCH_CONF,
    TCP_PUNCH_LAN,
)


def nat_mapping_to_port_alloc(nat_mappings):
    """Convert a list of NATMapping objects into PortAlloc entries for the punch engine."""
    out = []
    for m in nat_mappings:
        out.append(PortAlloc(src_port=m.local, dest_port=m.remote))

    return out


def nat_predict_states(dest_mappings, state):
    """Advance the NAT prediction state machine and return the new (state, side) tuple."""
    # bool of dest_mappings, start state, to state.
    progressions = [
        [False, None, INITIATED_PREDICTIONS],
        [True, None, RECEIVED_PREDICTIONS],
        [True, INITIATED_PREDICTIONS, UPDATED_PREDICTIONS],
    ]

    # What protocol 'side' corresponds to a state.
    sides = {
        INITIATED_PREDICTIONS: INITIATOR,
        UPDATED_PREDICTIONS: INITIATOR,
        RECEIVED_PREDICTIONS: RECIPIENT,
    }

    # Progress the state machine.
    for progression in progressions:
        from_recv, from_state, to_state = progression
        if from_recv != bool(dest_mappings):
            continue

        if from_state != state:
            continue

        return (to_state, sides[to_state])

    raise AssertionError("Invalid nat predict state progression.")


class NATPredictAlloc:
    """Allocates port mappings for NAT traversal using STUN-based prediction."""

    def __init__(self, stun_clients):
        self.af = stun_clients[0].af
        self.same_machine = False
        self.stun_clients = stun_clients
        self.side = self.state = None
        self.src_nat = self.dest_nat = None
        self.recv_mappings = []
        self.preloaded_mappings = []
        self.self_mappings = []

    def set_nat_info(self, src_nat=None, dest_nat=None):
        """Store the source and destination NAT info.

        Either side that is missing or unpredictable (typically symmetric +
        random delta) is replaced with RESTRICT_PORT_NAT + EQUAL_DELTA. The
        STUN-based NAT classifier can produce a false symmetric+random
        reading on hosts whose ephemeral allocator is non-monotonic
        (Windows XP being the obvious case), so we run the punch with a
        sane assumed shape rather than fail closed. A wrong guess just
        burns the plugin timeout; a right guess (the common case for
        consumer routers) lets the punch succeed.
        """
        nat_default = nat_info(RESTRICT_PORT_NAT, delta_info(EQUAL_DELTA, 0))
        self.src_nat = self.coerce_predictable(src_nat, "src") or copy.deepcopy(nat_default)
        self.dest_nat = self.coerce_predictable(dest_nat, "dest") or copy.deepcopy(nat_default)

    def coerce_predictable(self, nat, side):
        """Return ``nat`` if predictable; ``None`` to trigger the default."""
        if nat is None:
            return None
        if is_predictable_nat(nat):
            return nat
        delta = nat.get("delta") or {}
        log(fstr(
            "set_nat_info: {0}_nat unpredictable (type={1} delta_type={2}); "
            "falling back to RESTRICT_PORT_NAT + EQUAL_DELTA",
            (side, nat.get("type"), delta.get("type")),
        ))
        return None

    async def port_alloc(self, recv_mappings=None):
        """Progress the exchange state machine and return (port_allocs, is_end) for this round."""
        # Change protocol state transition.
        self.state, self.side = nat_predict_states(
            recv_mappings,
            self.state,
        )

        # Covers exchanging and receiving mappings.
        # These steps are required for success.
        fetch_states = [INITIATED_PREDICTIONS]
        fetch_states += [RECEIVED_PREDICTIONS]
        if self.state in fetch_states:
            self.send_mappings, self.preloaded_mappings = await nat_prediction(
                self.punch_mode,
                self.src_nat,
                self.dest_nat,
                self.stun_clients,
                recv_mappings=recv_mappings,
            )

            # Ii receive mapping isn't set use templates.
            self.recv_mappings = recv_mappings or copy.deepcopy(self.send_mappings)

            # Patch mappings for self punch.
            # This forces different ports to be used.
            if self.side == INITIATOR:
                self_punch_patch(self.punch_mode, self.recv_mappings)

            # Only things needed for protocol.
            return (nat_mapping_to_port_alloc(self.send_mappings), 0)

        # Update the mapping to match needed reply ports.
        # Optional step but improves success chance.
        if self.state == UPDATED_PREDICTIONS:
            # More updated list of their NAT predictions.
            self.recv_mappings = recv_mappings

            # Adjust our local bind ports if they need a specific
            # reply port to accept a connection.
            return (
                nat_mapping_to_port_alloc(
                    update_for_reply_ports(
                        self.punch_mode,
                        self.src_nat,
                        self.dest_nat,
                        self.preloaded_mappings,
                        self.recv_mappings,
                        self.send_mappings,
                    )
                ),
                1,
            )

    def set_punch_mode(self, same_machine, dest_ip="192.168.0.100"):
        """Determine and store the punch mode (LAN, remote, or self) from the destination IP."""
        self.punch_mode = get_punch_mode(self.af, str(dest_ip), self.same_machine)


async def workspace():
    """Interactive workspace for testing NATPredictAlloc locally."""
    nic = await Interface()
    stun_clients = await get_n_stun_clients(
        af=nic.supported()[0], n=5, proto=UDP, interface=nic, conf=PUNCH_CONF
    )

    # Generate port allocations based on NAT prediction algorithms.
    nat_predict = NATPredictAlloc(stun_clients)

    # Load test defaults.
    nat_predict.set_punch_mode()
    nat_predict.set_nat_info()
    send_alloc = await nat_predict.port_alloc()

    # Simulate receiving mappings by just using our own.
    # Obviously this is meaningless and real would come from a client.
    recv_mappings = nat_predict.send_mappings
    updated_alloc = await nat_predict.port_alloc(recv_mappings)


if __name__ == "__main__":
    asyncio.run(workspace())
