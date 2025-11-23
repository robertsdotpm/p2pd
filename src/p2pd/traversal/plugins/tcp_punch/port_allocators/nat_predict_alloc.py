import asyncio
import copy
from ......nic.nat.nat_predict import *
from ...punch_utils import *
from ...punch_defs import *
from ......utility.clock_skew import *
from ......net.asyncio.event_loop import *
from ..punch_defs import *

def nat_mapping_to_port_alloc(nat_mappings):
    out = []
    for m in nat_mappings:
        out.append(
            PortAlloc(
                src_port=m.local,
                dest_port=m.remote
            )
        )

    return out

def nat_predict_states(dest_mappings, state):
    # bool of dest_mappings, start state, to state.
    progressions = [
        [False, None, INITIATED_PREDICTIONS],
        [True, None, RECEIVED_PREDICTIONS],
        [True, INITIATED_PREDICTIONS, UPDATED_PREDICTIONS]
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
    
    raise Exception("Invalid nat predict state progression.")

class NATPredictAlloc():
    def __init__(self, stun_clients, same_machine=False):
        self.af = stun_clients[0].af
        self.same_machine = same_machine
        self.stun_clients = stun_clients
        self.side = self.state = None
        self.src_nat = self.dest_nat = None
        self.recv_mappings = []
        self.preloaded_mappings = []
        self.self_mappings = []


    def set_nat_info(self, src_nat=None, dest_nat=None):
        nat_default = nat_info(RESTRICT_PORT_NAT, delta_info(EQUAL_DELTA, 0))
        self.src_nat = src_nat or copy.deepcopy(nat_default)
        self.dest_nat = dest_nat or copy.deepcopy(nat_default)

    async def port_alloc(self, recv_mappings=None):
        # Change protocol state transition.
        self.state, self.side = nat_predict_states(
            recv_mappings,
            self.state,
        )

        # Covers exchanging and receiving mappings.
        # These steps are required for success.
        fetch_states  = [INITIATED_PREDICTIONS]
        fetch_states += [RECEIVED_PREDICTIONS]
        if self.state in fetch_states:
            self.send_mappings, self.preloaded_mappings = \
                await nat_prediction(
                    self.punch_mode,
                    self.src_nat,
                    self.dest_nat,
                    self.stun_clients,
                    recv_mappings=recv_mappings,
                )

            # Ii receive mapping isn't set use templates.
            self.recv_mappings = \
                recv_mappings or copy.deepcopy(
                    self.send_mappings
                )
            
            # Patch mappings for self punch.
            # This forces different ports to be used.
            if self.side == INITIATOR:
                self_punch_patch(
                    self.punch_mode,
                    self.recv_mappings
                )

            # Only things needed for protocol.
            return nat_mapping_to_port_alloc(self.send_mappings)
                
        # Update the mapping to match needed reply ports.
        # Optional step but improves success chance.
        if self.state == UPDATED_PREDICTIONS:
            # More updated list of their NAT predictions.
            self.recv_mappings = recv_mappings

            # Adjust our local bind ports if they need a specific
            # reply port to accept a connection.
            return nat_mapping_to_port_alloc(
                update_for_reply_ports(
                    self.punch_mode,
                    self.src_nat,
                    self.dest_nat,
                    self.preloaded_mappings,
                    self.recv_mappings,
                    self.send_mappings,
                )
            )

    def set_punch_mode(self, dest_ip="192.168.0.100"):
        self.punch_mode = get_punch_mode(
            self.af,
            str(dest_ip),
            self.same_machine
        )

async def workspace():
    nic = await Interface()
    stun_clients = await get_n_stun_clients(
        af=nic.supported()[0],
        n=5,
        proto=UDP,
        interface=nic,
        conf=PUNCH_CONF
    )

    # Generate port allocations based on NAT prediction algorithms.
    nat_predict = NATPredictAlloc(stun_clients)

    # Load test defaults.
    nat_predict.set_punch_mode()
    nat_predict.set_nat_info()
    send_alloc = await nat_predict.port_alloc()
    print(send_alloc)

    # Simulate receiving mappings by just using our own.
    # Obviously this is meaningless and real would come from a client.
    recv_mappings = nat_predict.send_mappings
    updated_alloc = await nat_predict.port_alloc(recv_mappings)
    print(updated_alloc) 

if __name__ == "__main__":
    asyncio.run(workspace())