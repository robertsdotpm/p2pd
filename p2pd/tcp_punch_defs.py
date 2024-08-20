"""
- seperate lists for everything
- internal functions
- io spread throughout

- goals:
    - seperate data processing funcs that can be fed results
    - io in their own funcs
    - 

current layout:
    IO:
        - choose local ports to use
        - edge-case for initial test for delta type nats
            - get first mapping (uses a high port)
                - is this the same as the other func
        - main i/o to get a prediction (from another func)
    Data:
        - main data processing of results 
            - seems to just been for the same duplicate logic ?

"""

from .utils import *
from .nat import *

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
    def __init__(self, mapping, sock=None):
        check_mapping(mapping)
        self.local = mapping[0]
        self.reply = mapping[1]
        self.remote = mapping[2]
        self.sock = sock

class NATMappings():
    def __init__(self, mappings):
        check_mappings_len(mappings)
        self.mappings = strip_duplicate_mappings(mappings)

nat_map = NATMapping([32000, -1, 32000])
print(nat_map)

def process_nat_predictions(results):
    mappings = NATMappings(
        [NATMapping(r) for r in results]
    )

async def get_initial_mapping(stun_client):
    nic = stun_client.interface
    af = stun_client.af
    get_mapping = stun_client.get_mapping
    for _ in range(0, 5):
        try:
            # Reserve a sock for use.
            _, high_port = await get_high_port_socket(
                nic.route(af),
                sock_type=TCP,
            )

            # Bind to a sock with that port.
            route = await nic.route(af).bind(
                port=high_port
            )

            # Determine associated remote port.
            local, remote, sock = await get_mapping(
                # Upgraded to a pipe.
                pipe=route
            )

            #socket.setsockopt(s, socket.SO_REUSEPORT)
            return NATMapping(
                [local, -1, remote],
                sock
            )
        except:
            continue

    raise Exception("high port sock fail.")

def get_mapping_templates(use_stun_port, use_range, test_no):
    mappings = []
    for _ in range(0, test_no):
        # Default port for when there is a
        # [port restrict, rand delta] NAT.
        if use_stun_port:
            mappings.append(
                NATMappings([STUN_PORT, -1, -1])
            )
            break
        else:
            mappings.append(
                NATMappings([
                    from_range(use_range), -1, -1
                ])
            )

    return mappings

def init_predictions(mode, src_nat, dest_nat, recv_mappings, test_no):
    # Set test_no based on recipients test no.
    # [[remote port, required reply port], ...]
    if recv_mappings is not None:
        test_no = len(recv_mappings)

    # Patch NAT if it's not remote.
    if mode in [TCP_PUNCH_LAN, TCP_PUNCH_SELF]:
        src_nat = nat_info(
            OPEN_INTERNET,
            delta_info(NA_DELTA, 0)
        )

        dest_nat = nat_info(
            OPEN_INTERNET,
            delta_info(NA_DELTA, 0)
        )

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

    recv_mappings.use_range = use_range
    return src_nat, dest_nat, recv_mappings

async def mock_nat_prediction(mode, src_nat, dest_nat, stun_client, recv_mappings=None, test_no=8):
    # Setup nats and initial mapping templates.
    # The mappings will be filled in with details.
    src_nat, dest_nat, recv_mappings = init_predictions(
        mode,
        src_nat,
        dest_nat,
        recv_mappings,
        test_no
    )

    # Used to help traverse delta type NATs.
    if src_nat["delta"]["type"] in DELTA_N:
        last_mapped = await get_initial_mapping(
            stun_client
        )
    else:
        last_mapped = None  

    # Use default ports for client if unknown
    # or try use their ports if known.
    tasks = []
    results = []
    for i in range(0, len(recv_mappings)):
        # Predict our mappings.
        # Try to match our ports to any provided mappings.
        task = get_single_mapping(
            # Punching mode.
            mode,

            # Try match this mapping.
            recv_mappings[i],

            # A mapping fetch from STUN.
            # Only set depending on certain NATs.
            last_mapped,

            # Uses an range compatible with both NATs for mappings.
            # Otherwise uses a range compatible with our_nat.
            recv_mappings.use_range,

            # Info on our NAT type and delta.
            src_nat,

            # Reference to do a STUN request to get a mapping.
            stun_client
        )