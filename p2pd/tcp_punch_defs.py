from .utils import *

INITIATED_PREDICTIONS = 1
RECEIVED_PREDICTIONS = 2
UPDATED_PREDICTIONS = 3
INITIATOR = 1
RECIPIENT = 2
MAX_PREDICT_NO = 100

def check_mapping(mapping):
    for port in mapping:
        # Means not applicable.
        if port == -1:
            continue

        if not valid_port(port):
            raise Exception(f"invalid mapping {mapping}")
        
    if mapping[0] <= 1024:
        raise Exception(f"invalid low port for mapping")
        
def check_mappings_len(mappings):
    if not len(mappings):
        raise Exception("Invalid mapping len 0")

    if len(mappings) > MAX_PREDICT_NO:
        raise Exception("Invalid mappings len 1")

def strip_duplicate_mappings(mappings):
    remote_list = []
    reply_list = []
    local_list = []
    filtered_list = []
    for mapping in mappings:
        if mapping.local in local_list:
            continue

        if mapping.reply in reply_list:
            continue

        if mapping.remote in remote_list:
            continue

        remote_list.append(mapping.remote)
        reply_list.append(mapping.reply)
        local_list.append(mapping.local)
        filtered_list.append(mapping)

    return filtered_list

class NATMapping():
    def __init__(self, mapping):
        check_mapping(mapping)
        self.local = mapping[0]
        self.reply = mapping[1]
        self.remote = mapping[2]

    
"""
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
"""

class NATMappings():
    def __init__(self, mappings):
        check_mappings_len(mappings)
        self.mappings = strip_duplicate_mappings(mappings)

nat_map = NATMapping([32000, -1, 32000])
print(nat_map)