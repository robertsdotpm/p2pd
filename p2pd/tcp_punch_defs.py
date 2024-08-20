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
    to_check = mapping[:]

    # Don't bother checking reply port.
    del to_check[1]

    # Check rest of ports: local and remote.
    for port in to_check:
        if not valid_port(port):
            raise Exception(f"invalid mapping {mapping}")
        
    # These require root.
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

nat_map = NATMapping([32000, 0, 32000])
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
                [local, 0, remote],
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
                NATMappings([STUN_PORT, 0, 1234])
            )
            break
        else:
            mappings.append(
                NATMappings([
                    from_range(use_range), 0, 1234
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

async def preload_mappings(no, stun_client):
    # Get a mapping to use.
    tasks = []
    mappings = []
    for _ in range(0, no):
        task = stun_client.get_mapping()
        tasks.append(task)

    results = await asyncio.gather(*tasks)
    result = strip_none(results)
    for result in results:
        local, remote, s = result
        mapping = NATMapping([local, 0, remote], s)
        mappings.append(mapping)

    return mappings

def mock_get_single_mapping(mode, rmap, last_mapped, use_range, our_nat, preloaded_mapping, step=1000):
    # Allow last mapped to be modified from inside func.
    last_local = last_mapped.local
    last_remote = last_mapped.remote

    # Need to bind to a specific port.
    remote_port = rmap.remote
    reply_port = rmap.reply
    bind_port = reply_port or remote_port

    """
    Normally the code tries to use the same port as
    the recipient to simplify the code and make things
    more resilient. But if you're trying to punch yourself
    using the same local port will be impossible. Choose
    a non-conflicting port.
    """
    if mode == TCP_PUNCH_SELF:
        remote = field_wrap(
            remote_port + step, 
            [2001, MAX_PORT]
        )

        return NATMapping([
            remote,
            0,
            remote,
        ])
    
    # If we're port restricted specify we're happy to use their mapping.
    # This may not be possible if our delta is random though.
    our_reply = bind_port if our_nat["type"] == RESTRICT_PORT_NAT else 0

    # Use their mapping as-is.
    if our_nat["is_open"]:
        return NATMapping([
            bind_port,
            0,
            bind_port
        ])

    # If preserving try use their mapping.
    if our_nat["delta"]["type"] == EQUAL_DELTA:
        if not in_range(bind_port, our_nat["range"]):
            bind_port = from_range(use_range)

        return NATMapping([
            bind_port,
            0,
            bind_port
        ])

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
        return NATMapping([
            next_local,
            our_reply,
            bind_port
        ])
    
    """
    The routers NATs allocate mappings from a known range as
    determined by doing an inital large number of STUN tests.
    This means that when near the end of a range an
    'independent' or 'dependent' type NAT will wrap around
    back to the start of the range.

    The problem with this is if the ranges provided to the
    function aren't precise then when the ports 'wrap around'
    they will land on ports before the provided range.
    This means that the predicted port will be wrong and
    the hole punching will fail.

    The ranges need to be precise should they not be
    from 1 - MAX_PORT and use these type of deltas.
    Increasing the test_no and rounding to powers of 2
    may help to increase accuracy of the ranges.
    """

    # Poor concurrency support.
    if our_nat["delta"]["type"] == INDEPENDENT_DELTA:
        # We can use anything for a local port.
        # The remote mappings have a pattern regardless of local tuples.
        next_local = from_range([2000, MAX_PORT])
        next_remote = field_wrap(
            last_remote + our_nat["delta"]["value"],
            use_range
        )

        # Return port predictions.
        # These allocations apply even if strict port NAT.
        # But we tell other side to use a specific mapping for coordination.
        last_mapped = [next_local, next_remote]
        return NATMapping([
            next_local,
            our_reply,
            next_remote
        ])

    # Poor concurrency support.
    if our_nat["delta"]["type"] == DEPENDENT_DELTA:
        next_local = port_wrap(last_local + 1)
        next_remote = field_wrap(
            last_remote + our_nat["delta"]["value"],
            use_range
        )

        # Return port predictions.
        # These allocations apply even if strict port NAT.
        # But we tell other side to use a specific mapping for coordination.
        last_mapped = [next_local, next_remote]
        return NATMapping([
            next_local, 
            our_reply,
            next_remote
        ])

    # Delta type is random -- get a mapping from STUN to reuse.
    # If we're port restricted then set our reply port to the STUN port.
    if our_nat["type"] in PREDICTABLE_NATS:
        # Calculate reply port.
        our_reply = 3478 if our_nat["type"] == RESTRICT_PORT_NAT else 0
        # TODO: Could connect to STUN port in their range.

        # Return results.
        return NATMapping([
            preloaded_mapping.local,
            our_reply,
            preloaded_mapping.remote
        ])
    
    """
    The hardest NATs to support are 'symmetric' type NATs that only
    allow mappings to be used per [src ip, src port, dest ip, dest port].
    The only way to support symmetric NATs is if they also have
    a non-random delta. If this point is reached then they are likely
    are heavily restricted NAT with a random delta.
    """

    raise Exception("Can't predict this NAT type.")


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

    # Preload nat predictions then
    # mock single mapping can be a function.
    preloaded_mappings = await preload_mappings(
        len(recv_mappings),
        stun_client
    )
    assert(len(preloaded_mappings))

    # Use default ports for client if unknown
    # or try use their ports if known.
    results = []
    for i in range(0, len(recv_mappings)):
        # Default to using last mapped.
        try:
            preloaded_mapping = preloaded_mappings[i]
        except IndexError:
            preloaded_mapping = preloaded_mappings[0]

        # Predict our mappings.
        # Try to match our ports to any provided mappings.
        result = mock_get_single_mapping(
            # Punching mode.
            mode,

            # Try match this mapping.
            recv_mappings[i],

            # A mapping fetch from STUN.
            # Only set depending on certain NATs.
            last_mapped,

            # Uses a range compatible with both NATs
            # Otherwise uses our range.
            recv_mappings.use_range,

            # Info on our NAT type and delta.
            src_nat,

            # Get a result instantly.
            preloaded_mapping,
        )

        # Save prediction.
        results.append(result)