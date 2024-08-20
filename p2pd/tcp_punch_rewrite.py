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

def get_nat_predictions(mode, stun_client, src_nat, dest_nat):
    return

class TCPPunchFactory:
    def __init__(self):
        # by pipe_id, node_id
        self.clients = {}

class NATMapping():
    def __init__(self, local, reply, remote):
        self.local = local
        self.reply = reply
        self.remote = remote

class TCPPuncher():
    def __init__(self, src_info, dest_info, node):
        self.src_info = src_info
        self.dest_info = dest_info
        self.node = node
        self.set_interface()
        self.set_punch_mode()

    def set_interface(self):
        self.if_index = self.src_info["if_index"]
        self.interface = self.node.ifs[self.if_index]

    def set_punch_mode(self):
        self.punch_mode = 0

    def proto_predict_mappings(self, stun_client, recv_mappings=None):
        mappings = get_nat_predictions(
            self.punch_mode,
            stun_client,
            self.interface.nat,
            self.dest_info["nat"]
        )

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

alice_punch.proto_predict_mappings(stun_client)