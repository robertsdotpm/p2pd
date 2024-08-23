"""
Old module problems:

- God object - lets use isolated classes that encapsulate state for one set of peers.
    - factory management with member objects in same object
    - no separation of concerns
- 1300 lines - move utils to own file, do reset of cleanup later
- multiple data formats for the mappings?
    - mappings data type and logic scattered throughout
- duplicate code for init mappings and recv init mappings
- do_punching
    - static method that would be better in a process module
    - remote mode and local mode almost exactly the same
- lengthy test code that is outdated
"""

"""
proto uses 'our maps' map info to their maps
'their maps'
- list of lists which are [remote reply local]
- proto also uses ntp meet time

map_info is from 'get_nat_predictions'
    - so wrong format

This code needs to be moved to the get_nat_predictions func.
    - pass it a side parameter
    # initiator
    if mode == TCP_PUNCH_SELF:
        rmaps = copy.deepcopy(map_info)
        patch_map_info_for_self_punch(rmaps)
        rmaps = map_info_to_their_maps(rmaps)

    # recipient
    if mode != TCP_PUNCH_SELF:
        x = len(map_info["reply"])
        y = len(their_maps)
        for i in range(0, min(x, y)):
            if map_info["reply"][i]:
                # Overwrite their remote port.
                their_maps[i][0] = map_info["reply"][i]

    # recipient
    if mode == TCP_PUNCH_SELF:
    our_maps = copy.deepcopy(map_info)
    patch_map_info_for_self_punch(our_maps)
    our_maps = map_info_to_their_maps(map_info)

- in that light:
    - get nat predictions probably needs to be broken into funcs
    - this function is ungodly
"""

from .nat_rewrite import *
from .tcp_punch_utils import *

class TCPPunchFactory:
    def __init__(self):
        # by pipe_id, node_id
        self.clients = {}

class TCPPuncher():
    def __init__(self, src_info, dest_info, node, same_machine=False):
        af = self.af = src_info["af"]
        self.node = node
        self.src_info = src_info
        self.dest_info = dest_info
        self.set_interface()
        self.set_punch_mode()
        self.stun = node.stun_clients[af][self.if_index]
        self.state = None

    def set_interface(self):
        self.if_index = self.src_info["if_index"]
        self.interface = self.node.ifs[self.if_index]

    def set_punch_mode(self):
        self.punch_mode = get_punch_mode(
            self.af,
            str(self.dest_info["ip"]),
            self.same_machine
        )

    def set_coordination(self):
        pass

    def get_ntp_meet_time(self):
        return self.sys_clock.time() + Dec(NTP_MEET_STEP)
    
    async def proto(self, recv_mappings=None, start_time=None):
        # Change protocol state transition.
        self.state, self.side = tcp_puncher_states(
            recv_mappings,
            self.state,
        
        )

        # Covers exchanging and receiving mappings.
        # These steps are required for success.
        fetch_states  = [INITIATED_PREDICTIONS]
        fetch_states += [RECEIVED_PREDICTIONS]
        if self.state in fetch_states:
            self.send_mappings, preloaded_mappings = \
                await mock_nat_prediction(
                    self.mode,
                    self.src_info["nat"],
                    self.dest_info["nat"],
                    self.stun,
                    recv_mappings=recv_mappings,
                )

            # IF receive mapping isn't set use initial value.
            self.recv_mappings = \
                recv_mappings or self.send_mappings
            
            # Set meeting start time.
            arrange_time = self.get_ntp_meet_time()
            self.start_time = \
                start_time or arrange_time

            # Only things needed for protocol.
            return self.send_mappings, self.start_time
                
        # Update the peers mapping to match needed reply ports.
        # Optional step but improves success chance.
        if self.state == UPDATED_PREDICTIONS:
            await update_nat_predictions(
                self.mode,
                src_nat,
                dest_nat,
                preloaded_mappings,
                self.send_mappings,
                recv_mappings
            )

            return 1


##################################################
# Workspace

class MockInterface:
    def __init__(self):
        self.nat = None

class NodeMock:
    def __init__(self):
        self.ifs = [MockInterface()]

alice_node = NodeMock()
bob_node = NodeMock()

ds_info = {
    "nat": None,
    "if_index": 0
}

src_info = ds_info
dest_info = ds_info

stun_client = "placeholder"

pipe_id = "my pipe"
alice_node_id = "alice node id"
bob_node_id = "bob node id"
alice_dest = {}
bob_dest = {}

alice_punch = TCPPuncher(src_info, dest_info, alice_node)
bob_punch = TCPPuncher(src_info, dest_info, bob_node)

print(alice_punch)
print(bob_punch)

n_map = NATMapping([23000, -1, 23000])
recv_mappings = [n_map]
alice_punch.proto_predict_mappings(stun_client)
alice_punch.proto_predict_mappings(stun_client, recv_mappings)
bob_punch.proto_predict_mappings(stun_client, recv_mappings)
