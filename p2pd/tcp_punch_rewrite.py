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
- 
"""

from .tcp_punch_defs import *
from .tcp_punch_utils import *

class TCPPunchFactory:
    def __init__(self):
        # by pipe_id, node_id
        self.clients = {}

class TCPPuncher():
    def __init__(self, src_info, dest_info, node):
        self.node = node
        self.src_info = src_info
        self.dest_info = dest_info
        self.set_interface()
        self.set_punch_mode()
        self.state = None

    def set_interface(self):
        self.if_index = self.src_info["if_index"]
        self.interface = self.node.ifs[self.if_index]

    def set_punch_mode(self):
        self.punch_mode = 0

    def proto_predict_mappings(self, stun_client, dest_mappings=None):
        # Change protocol state transition.
        self.state = tcp_puncher_states(
            dest_mappings,
            self.state
        
        )

        # Record NAT predictions.
        self.dest_mappings = dest_mappings
        self.src_mappings = get_nat_predictions(
            self.punch_mode,
            stun_client,
            self.interface.nat,
            self.dest_info["nat"]
        )

        return self.src_mappings

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

n_map = NATMapping(1, 2, 3)
recv_mappings = [n_map]
alice_punch.proto_predict_mappings(stun_client)
alice_punch.proto_predict_mappings(stun_client, recv_mappings)
bob_punch.proto_predict_mappings(stun_client, recv_mappings)
print(bob_punch.state)