import random
from ...net.address import *
from .nat_defs import *


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
async def delta_test(stun_clients, test_no=8, threshold=5, concurrency=True):
    """
    - When getting a list of ports to use for tests
    calculate the port to start at.
    - If another start port has been used in other tests
    make sure not to choose a starting port that conflicts
    with a port in another tests range.
    - port_dist = distance between successive ports
    from start_port to test_no, incremented by port_dist.
    """
    assert(len(stun_clients) >= test_no)
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
                
                # Avoid relying on any one server. 
                stun_client = random.choice(stun_clients)
                
                # Get mapping using specific source port.
                route = None
                if stun_client.interface is not None:
                    iface = stun_client.interface
                    route = iface.route(stun_client.af)
                    await route.bind(port=src_port)

                """
                Todo: manually chosen source ports
                aren't guaranteed to succeed due to
                conflicts and you're not checking for
                failure.
                """

                ret = await stun_client.get_mapping(
                    pipe=route
                )

                if ret is None:
                    log("No stun reply in delta map")
                    return None
                else:
                    local, mapped, s = ret

                # Return mapping results.
                return [local, mapped, s]

            # Allow for tests to be done concurrently.
            tasks.append(
                async_wrap_errors(
                    asyncio.wait_for(
                        result_wrapper(src_port),
                        2
                    )
                )
            )

        return tasks

    def get_delta_value(delta_no, dist_no, local_dist, preserv_dist, results):
        if results is None:
            return

        for i in range(0, len(results)):
            try:
                # Skip invalid results
                if results[i] is None:
                    continue
                
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
            except Exception:
                log_exception()

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
            if result is not None:
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
    for p in socks:
        if p is None:
            continue
            
        await p.close()
        
    socks = []

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
def nats_intersect(our_nat, their_nat, test_no):
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

    # Ensure bind ports don't end up in low port ranges.
    if use_range[0] <= 1024:
        use_range[0] = 2000
        if use_range[0] >= use_range[1]:
            raise Exception("Can't find intersecting port range.")
        
    return use_range

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

