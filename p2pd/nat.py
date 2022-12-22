import random
from .address import *

STUN_PORT = 3478
MAX_MAP_NO = 100

# NAT TYPES ---------------------------------------------

# No NAT at all.
OPEN_INTERNET = 1

# There is no NAT but there is some kind of firewall.
SYMMETRIC_UDP_FIREWALL = 2

# Mappings are made for local endpoints.
# Then any destination can use the mapping to reach the local enpoint.
# Note: May be incorrectly detected if using TCP.
FULL_CONE = 3

# NAT reuses mapping if same src ip and port is used.
# Destination must be white listed. It can use any port to send replies on.
# Endpoint-independent
# Note: May be incorrectly detected if using TCP.
RESTRICT_NAT = 4

# Mappings reused based on src ip and port.
# Destination must be white listed and use the port requested by recipient.
# Endpoint-independent (with some limitations.)
# Note: May be incorrectly detected if using TCP.
RESTRICT_PORT_NAT = 5

# Different mapping based on outgoing hosts.
# Even if same source IP and port reused.
# AKA: End-point dependent mapping.
SYMMETRIC_NAT = 6

# No response at all.
BLOCKED_NAT = 7
# ---------------------------------------------------------

# DELTA types: ------------------
# Mappings are easy to reuse and reach.
NA_DELTA = 1 # Not applicable.
EQUAL_DELTA = 2
PRESERV_DELTA = 3 # Or not applicable like in open internet.
INDEPENDENT_DELTA = 4
DEPENDENT_DELTA = 5
RANDOM_DELTA = 6
# -------------------------------

EASY_NATS = [OPEN_INTERNET, FULL_CONE]
DELTA_N = [
    # Remote = Local.
    EQUAL_DELTA,

    # Remote x - y = local x - y
    PRESERV_DELTA,

    # Remote x; y = remote x + delta, local = anything
    INDEPENDENT_DELTA,

    # Remote x; y = remote x + delta only when local x + delta
    DEPENDENT_DELTA
]

# The NATs here have various properties that allow their
# mappings to be predictable under certain conditions.
PREDICTABLE_NATS = [
    # Once open - anyone can use the mapping.
    FULL_CONE,

    # Same local IP + port = same mapping.
    RESTRICT_NAT,
    
    # Same as above but reply port needs to match original dest.
    RESTRICT_PORT_NAT,
]

# NAT types that require specific reply ports.
FUSSY_NATS = [
    RESTRICT_PORT_NAT,
]

# Peer will be unreachable.
BLOCKING_NATS = [
    BLOCKED_NAT
]

# Punch modes.
TCP_PUNCH_LAN = 1
TCP_PUNCH_REMOTE = 2
TCP_PUNCH_SELF = 3

# Convenience funcs.
# delta, nat_type
f_is_open = lambda n, d: n in [OPEN_INTERNET, SYMMETRIC_UDP_FIREWALL]
f_can_predict = lambda n, d: n in PREDICTABLE_NATS
def f_is_hard(n, d):
    not_easy = n not in EASY_NATS
    return not_easy and d["type"] not in [PRESERV_DELTA, EQUAL_DELTA]

def delta_info(delta_type, delta_value):
    return {
        "type": delta_type,
        "value": delta_value
    }

def nat_info(nat_type=None, delta=None, map_range=None):
    # Defaults.
    delta = delta or delta_info(RANDOM_DELTA, 0)
    map_range = map_range or [1, MAX_PORT]
    nat_type = nat_type or RESTRICT_PORT_NAT

    # Main NAT dic with simple lookup types.
    nat = {
        "type": nat_type,
        "delta": delta, # type, value
        "range": map_range, # start, stop
        "is_open": f_is_open(nat_type, delta),
        "can_predict": f_can_predict(nat_type, delta),
        "is_hard": f_is_hard(nat_type, delta)
    }

    # Setup whether this NAT type is good for concurrent punches.
    bad_delta = delta["type"] in [INDEPENDENT_DELTA, DEPENDENT_DELTA]
    nat["is_concurrent"] = nat_type in EASY_NATS or not bad_delta

    # Return results.
    return nat

def valid_mappings_len(mappings):
    if not len(mappings):
        return 0

    if len(mappings) > MAX_MAP_NO:
        return 0

    return 1

"""
The algorithm for selecting the same connection is based on
choosing the highest remote port on the 'master.'
Thus, if multiple cons have the same remote
port (on port over-loaded NATs - this is possible) --
then the code will fail. What we want is unique mappings.
"""
def rmaps_strip_duplicates(rmaps):
    remote_list = []
    reply_list = []
    local_list = []
    filtered_list = []
    for rmap in rmaps:
        remote, reply, local = rmap
        if remote in remote_list:
            continue

        if reply in reply_list:
            continue

        if local in local_list:
            continue
        
        remote_list.append(remote)
        reply_list.append(reply)
        local_list.append(local)
        filtered_list.append(rmap)

    return filtered_list

def is_valid_rmaps(rmaps):
    if type(rmaps) != list:
        return 0

    for e in rmaps:
        if type(e) != list:
            return 0

        if len(e) != 3:
            return 0

        for port in e:
            if type(port) != int:
                return 0

        # remote.
        if not valid_port(e[0]):
            return 0

        # local.
        if not valid_port(e[2]):
            return 0

        # check reply.
        if e[1]:
            if not valid_port(e[1]):
                return 0

    return 1

"""
Determine any numerical patterns in port mapping allocations.

Symmetric NATs use a new mapping for each destination + port.
By default this means you can't predict mappings. However,
it may still be possible if the NAT uses a predictable value
between mappings -- hence this is checked for.

The code here also distinguishes between 'dependent' and
'independent' delta types. Independent delta means NAT
mappings increase by n no matter what the source port
might be. It may be useful to differentiate this from a
delta type that is dependent on local ports because it's
more likely to have collisions seeing as how any outgoing
connection will increase the mapping counter.

Therefore -- this NAT type is poorly suited to concurrent
TCP hole punching and worth making the distinction for
even though the port prediction code for both is identical.

Note: Some delta type detections dependent on comparing the
value of the previous result. If concurrency is enabled
they results will be 'out of order' or unpredictable and
lead to invalid results. Concurrency is thus disabled.
This code is very badly written but it's at least tested.
"""
async def delta_test(stun_client, test_no=8, threshold=5, proto=DGRAM, group="map", concurrency=True):
    """
    - When getting a list of ports to use for tests
    calculate the port to start at.
    - If another start port has been used in other tests
    make sure not to choose a starting port that conflicts
    with a port in another tests range.
    - port_dist = distance between successive ports
    from start_port to test_no, incremented by port_dist.
    """
    def get_start_port(port_dist, range_info=[]):
        # Random port skipping reserved and max ports.
        rand_start_port = lambda: random.randrange(
            4000, MAX_PORT - (test_no * port_dist)
        )

        # Return if no other port range to check for conflicts.
        if not range_info:
            return rand_start_port()
        else:
            new_start_port = None
            do_retry = 1
            while do_retry:
                # Try a rand port as the starting port.
                do_retry = 0
                new_start_port = rand_start_port()
                for other_range in range_info:
                    # Range is other_start_port to other_end_port inclusive.
                    other_dist, other_start_port = other_range
                    other_end_port = other_start_port + (test_no * other_dist)

                    # If it's in the same range as other_start_port retry.
                    lower_bound = new_start_port >= other_start_port
                    upper_bound = new_start_port <= other_end_port
                    if lower_bound and upper_bound:
                        do_retry = 1
                        break

            return new_start_port

    # Create a list of tasks to get a mapping for a port range.
    def get_port_tests(start_port, port_dist=1):
        # Return task list for tests.
        tasks = []
        for i in range(0, test_no):
            # If start is defined then calculate a list of ports.
            # Otherwise the OS assigns an unused port.
            if start_port:
                src_port = start_port + (i * port_dist)
            else:
                src_port = random.randrange(4000, MAX_PORT)

            # Get the mapping using STUN.
            async def result_wrapper(src_port):
                # Make sure port isn't in the reserved range.
                if src_port < 4000 and src_port != 0:
                    raise Exception("src less than 4k in mapping behavior.")

                # Get mapping using specific source port.
                _, s, local, mapped, _, _ = await stun_client.get_mapping(
                    proto,
                    do_close=0,
                    source_port=src_port,
                    group=group
                )

                # Return mapping results.
                return [local, mapped, s]

            # Allow for tests to be done concurrently.
            tasks.append(result_wrapper(src_port))

        return tasks

    def get_delta_value(delta_no, dist_no, local_dist, preserv_dist, results):
        for i in range(0, len(results)):
            # Unpack result.
            local, mapped, s = results[i]
            socks.append(s)
            if mapped is None:
                continue

            # Set previous result if available.
            prev_result = None
            if i != 0:
                if results[i - 1][MAPPED_INDEX] is not None:
                    prev_result = results[i - 1]

            # Preserving NAT.
            if local == mapped:
                delta_no[EQUAL_DELTA] = delta_no.get(EQUAL_DELTA, 0) + 1

            # Comparison tests.
            if prev_result is not None:
                # Skip invalid results.
                prev_local = prev_result[LOCAL_INDEX]
                prev_mapped = prev_result[MAPPED_INDEX]
                if not prev_local or not prev_mapped:
                    continue

                # Preserving delta if true.
                _local_dist = abs(field_dist(local, prev_local, MAX_PORT))
                mapped_dist = abs(field_dist(mapped, prev_mapped, MAX_PORT))
                if mapped_dist == _local_dist:
                    # Otherwise its preserving.
                    if mapped != local:
                        preserv_dist[mapped_dist] = 1
                        delta_no[PRESERV_DELTA] = delta_no.get(PRESERV_DELTA, 0) + 1
                else:
                    # Delta mapping dist.
                    # Plus one NAT type now here.
                    if _local_dist != 1:
                        dist_no[mapped_dist] = dist_no.get(mapped_dist, 0) + 1
                    else:
                        local_dist[mapped_dist] = local_dist.get(mapped_dist, 0) + 1

    # Offset names for port test results.
    LOCAL_INDEX = 0 # Source port.
    MAPPED_INDEX = 1 # External mapped port.
    SOCK_INDEX = 2 # Ref to sock used for STUN test.
    socks = []

    # Used for info about port ranges used for tests.
    # [ [ dist, start_port ], ... ]
    range_info = []

    # Do first port tests with random local ports.
    tasks = get_port_tests(0)
    if concurrency:
        results = await asyncio.gather(*tasks)
    else:
        results = []
        for task in tasks:
            result = await task
            results.append(result)

    """
    Check for:
        equal delta: src_port == mapped_port
        preserving delta NATs: dist(src_a, src_b) == dist(map_a, map_b)
        delta n (independent): dist(map_a, map_b) == delta n
    """ 
    delta_no = {}
    dist_no = {}
    preserv_dist = {}
    local_dist = {}

    # Close previous sockets.
    get_delta_value(delta_no, dist_no, local_dist, preserv_dist, results)
    socks = await sock_close_all(socks)

    # See if any of the above tests succeeded.
    test_names = [ EQUAL_DELTA, PRESERV_DELTA ]
    if len(preserv_dist) <= 1:
        test_names = [ EQUAL_DELTA]

    for test_name in test_names:
        if test_name not in list(delta_no.keys()):
            continue

        no = delta_no[test_name]
        if no >= threshold:
            return delta_info( test_name, 0 )
    for port_dist in list(dist_no.keys()):
        no = dist_no[port_dist]
        if no >= threshold:
            return delta_info( INDEPENDENT_DELTA, port_dist )

    """
    Check for:
        dependent delta check = also requires delta increase in src port
        delta n (dependent): dist(map_a, map_b) == local src++
    """
    delta_no = {}
    dist_no = {}
    preserv_dist = {}
    local_dist = {}

    # Get mapping results for fixed delta.
    start_port = get_start_port(1, range_info)
    tasks = get_port_tests(start_port)
    if concurrency:
        results = await asyncio.gather(*tasks)
    else:
        results = []
        for task in tasks:
            result = await task
            results.append(result)

    get_delta_value(delta_no, dist_no, local_dist, preserv_dist, results)

    # Check for deltas that satisfy success threshold.
    for port_dist in list(local_dist.keys()):
        no = local_dist[port_dist]
        if no >= threshold:
            return delta_info( DEPENDENT_DELTA, port_dist )

    # Return delta value.
    return delta_info( RANDOM_DELTA, 0 )

"""
A NAT may only allocate mappings from within a fixed range.
Starlink's default router is an example of this.
It has an allocation range of like 35000 - MAX_PORT.
It probably chose to do this for security reasons.
E.g. most known services use low range ports. If it only
uses higher range ports for mappings it won't show up
for port scanners as much.
""" 
def nats_intersect_range(our_nat, their_nat, test_no):
    # Calculate intersection range.
    is_intersect = range_intersects(our_nat["range"], their_nat["range"])
    if is_intersect:
        # A range that represents an overlapping portion.
        # Between our[range] and their[range] if any.
        r = intersect_range(
            our_nat["range"],
            their_nat["range"]
        )

        # If range is long enough then use it.
        range_no = r[1] - r[0]
        if range_no >= test_no:
            use_range = r
        else:
            use_range = our_nat["range"]
    else:
        use_range = our_nat["range"]

    return use_range

###############################################################
# [ [ local, remote, reply, sock ] ... ]
async def get_single_mapping(mode, rmap, last_mapped, use_range, our_nat, stun_client):
    # Allow last mapped to be modified from inside func.
    last_local, last_remote = last_mapped

    # Need to bind to a specific port.
    remote_port, reply_port, their_local = rmap
    bind_port = reply_port or remote_port

    """
    Normally the code tries to use the same port as
    the recipient to simplify the code and make things
    more resilient. But if you're trying to punch yourself
    using the same local port will be impossible. Choose
    a non-conflicting port.
    """
    if mode == TCP_PUNCH_SELF:
        while 1:
            bind_port = random.randrange(2000, MAX_PORT)
            if bind_port != remote_port:
                break

    # If we're port restricted specify we're happy to use their mapping.
    # This may not be possible if our delta is random though.
    our_reply = bind_port if our_nat["type"] == RESTRICT_PORT_NAT else 0

    # Use their mapping as-is.
    if our_nat["is_open"]:
        return [[bind_port, bind_port, 0, None], last_mapped]

    # If preserving try use their mapping.
    if our_nat["delta"]["type"] == EQUAL_DELTA:
        if not in_range(bind_port, our_nat["range"]):
            bind_port = from_range(use_range)

        return [[bind_port, bind_port, 0, None], last_mapped]

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
        return [[next_local, bind_port, our_reply, None], last_mapped]

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
        return [[next_local, next_remote, our_reply, None], last_mapped]

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
        return [[next_local, next_remote, our_reply, None], last_mapped]

    # Delta type is random -- get a mapping from STUN to reuse.
    # If we're port restricted then set our reply port to the STUN port.
    if our_nat["type"] in PREDICTABLE_NATS:
        # Get a mapping to use.
        _, s, local_port, remote_port, _, _ = await stun_client.get_mapping(
            proto=STREAM
        )

        # Calculate reply port.
        our_reply = 3478 if our_nat["type"] == RESTRICT_PORT_NAT else 0
        # TODO: Could connect to STUN port in their range.

        # Return results.
        return [[local_port, remote_port, our_reply, s], last_mapped]

    """
    The hardest NATs to support are 'symmetric' type NATs that only
    allow mappings to be used per [src ip, src port, dest ip, dest port].
    The only way to support symmetric NATs is if they also have
    a non-random delta. If this point is reached then they are likely
    are heavily restricted NAT with a random delta.
    """

    raise Exception("Can't predict this NAT type.")

"""
The code in this function is mostly error checking for
'restricted port NATs.' It checks that its possible
to predict mappings based on the NAT types in play.
"""
def nats_can_predict(our_nat, their_nat):
    ###############################################################
    # Increase test no if its a restricted port NAT.
    our_strict = our_nat["type"] == RESTRICT_PORT_NAT
    other_strict = their_nat["type"] == RESTRICT_PORT_NAT
    if our_strict and other_strict:
        # Error scenario for two strict port NATs with rand deltas.
        our_rand_delta = our_nat["delta"]["type"] == RANDOM_DELTA
        their_rand_delta = their_nat["delta"]["type"] == RANDOM_DELTA
        if our_rand_delta or their_rand_delta:
            raise Exception("Two strict port nats need non-rand deltas.")

    # If either side is port restrict make sure its partner can satisfy reply port.
    use_stun_port = 0
    if our_strict or other_strict:
        for nats in [[our_nat, their_nat], [their_nat, our_nat]]:
            # Switch which side is restricted.
            # Both may be restricted -- in which case both need non-rand delta.
            strict, unrestrict = nats
            if unrestrict["type"] == RESTRICT_PORT_NAT:
                strict, unrestrict = unrestrict, strict

            # If strict side has rand delta and partner cant satisfy reply port.
            # There are multiple ways to satisfy the reply port which are checked.
            # Raise an error condition if certain failure.
            strict_rand_delta = strict["delta"]["type"] == RANDOM_DELTA
            if strict_rand_delta and unrestrict["is_hard"]:
                raise Exception("Unable to satisfy mapping for strict port type.")

            # The reply port here is the STUN port as they use STUN to get a mapping.
            # Unable to satisfy reply port due to allocation range.
            if strict_rand_delta and not in_range(STUN_PORT, unrestrict["range"]):
                raise Exception("Can't support reply port 3478 for strict NAT.")

            # Use STUN port when we generate the fake 'their_mappings.'
            """
            OS' usually require admin or root to listen to the first 1024 ports.
            It is quite convenient that STUN listens on port 3478 or some
            clients behind certain NATs would need to be run as root to
            match the reply port of its peer.
            """
            if strict_rand_delta:
                use_stun_port = 1

    return use_stun_port

# Generates a list of local ports to remote mapped ports,
# and / or required reply ports for TCP hole punching.
async def get_nat_predictions(mode, stun_client, our_nat, their_nat, their_maps=None, test_no=8):
    # List of ports to bind to.
    local_ports = []

    # Remote ports that our NAT will show.
    remote_ports = []

    # Indicates whether replies need to be from a certain remote port.
    reply_ports = []

    # Stun socks (if used.)
    stun_socks = []

    # Patch NAT if it's not remote.
    if mode in [TCP_PUNCH_LAN, TCP_PUNCH_SELF]:
        our_nat = nat_info(OPEN_INTERNET, delta_info(NA_DELTA, 0))
        their_nat = nat_info(OPEN_INTERNET, delta_info(NA_DELTA, 0))

    # Convenience func.
    def save_mapping(bind_p, remote_p=None, reply_p=0):
        if remote_p is None:
            remote_p = bind_p

        local_ports.append(bind_p)
        remote_ports.append(remote_p)
        reply_ports.append(reply_p)

    # Set test_no based on recipients test no.
    # [[remote port, required reply port], ...]
    if their_maps is not None:
        test_no = len(their_maps)

    # Pretend we have a list of mappings from a peer
    # even if we don't -- used to simplify code.
    use_stun_port = nats_can_predict(our_nat, their_nat)
    use_range = nats_intersect_range(our_nat, their_nat, test_no)
    if their_maps is None:
        their_maps = []
        for i in range(0, test_no):
            # Default port for when there is a [port restrict, rand delta] NAT.
            if use_stun_port:
                test_no = 1
                their_maps.append([STUN_PORT, 0, 0])
                break
            else:
                their_maps.append([from_range(use_range), 0, 0])

    # Set initial mapping needed for delta type NATs.
    last_mapped = [None, None]
    if our_nat["delta"]["type"] in DELTA_N:
        _, s, local_port, remote_port, _, _ = await stun_client.get_mapping(
            proto=STREAM
        )

        last_mapped = [local_port, remote_port]
        stun_socks.append(s)

    # Make a list of tasks to build port predictions.
    # Use default ports for client if unknown or try use their ports.
    tasks = []
    results = []
    for i in range(0, test_no):
        # Predict our mappings.
        # Try to match our ports to any provided mappings.
        task = get_single_mapping(
            # Punching mode.
            mode,

            # Try match this mapping.
            their_maps[i],

            # A mapping fetch from STUN.
            # Only set depending on certain NATs.
            last_mapped,

            # Uses an range compatible with both NATs for mappings.
            # Otherwise uses a range compatible with our_nat.
            use_range,

            # Info on our NAT type and delta.
            our_nat,

            # Reference to do a STUN request to get a mapping.
            stun_client
        )

        """
        Concurrent NAT types can use asyncio.gather.
        Non-concurrent NATs need to be executed in order.
        The reason for this is that on non-concurrent NATs
        the allocations rely on using an incrementing sequence
        of source ports. The order these are allocated couldn't
        be guaranteed if asyncio.gather were to be used.
        """
        if our_nat["is_concurrent"]:
            tasks.append(task)
        else:
            result = await task
            results.append(result)

    # Run tasks concurrently.
    if len(tasks):
        results = await asyncio.gather(*tasks)

    # Store results in correct indexes.
    for result in results:
        info, _ = result
        local, remote, reply, sock = info
        save_mapping(local, remote, reply)
        if sock is not None:
            stun_socks.append(sock)

    # Invalid state -- caller handle this pl0x.
    if not(len(local_ports)):
        raise Exception("Unable to predict mappings")

    ###############################################################
    # Make a list of duplicate offsets to strip.
    assert(len(local_ports) == len(remote_ports))
    assert(len(remote_ports) == len(reply_ports))
    check_lists = [ local_ports, remote_ports, reply_ports ]
    dups = [ [], [], [] ]
    offending_offsets = []
    for j in range(0, len(check_lists)):
        check_list = check_lists[j]
        for i in range(0, len(check_list)):
            if check_list in [ local_ports, reply_ports ]:
                if not check_list[i]:
                    continue

            if check_list[i] in dups[j]:
                offending_offsets.append(i)
                continue

            dups[j].append(check_list[i])
            
    # Delete the offending elements.
    # Offsets are adjusted to account for the
    # changed / new size of the list after changes.
    offending_offsets = sorted(offending_offsets)
    offending_offsets = to_unique(offending_offsets)
    for i in range(0, len(offending_offsets)):
        offset = offending_offsets[i] - i
        for check_list in check_lists:
            del check_list[offset]

    # Local ports are relative to a given NIC IP
    # hence we also return the interface.
    return {
        "interface": stun_client.interface,
        "af": stun_client.af,
        "local": local_ports,
        "remote": remote_ports,
        "reply": reply_ports,
        "stun_socks": stun_socks,
        "default_maps": their_maps,
        "last_mapped": last_mapped
    }