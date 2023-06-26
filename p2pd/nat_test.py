"""
When using UDP in network programming its common to write
code so that it has simple loops to retry sending packets if
no response is received. The problem is: if any packets are lost
the time spent waiting keeps accumulating to the cost of a round-trip.

The problem is made worse when you consider slow-downs in DNS and
the often unreliable nature of relying on community servers for
STUN code. If one is not careful they quickly end up with an
algorithm that is prohibitively slow in the best case and quite
unreliable in the worst case.

The original algorithm for doing STUN tests for RFC 3489 used
incremental tests and was very brittle. However -- due to the
nature of how these tests work -- it became clear to me that it was
possible to paralyze the tests into two main phases if a STUN
server's primary and secondary IP were known beforehand.

Phase 1 tests for [open NAT and full cone] while phase 2 tests for
[restrict ip and restrict port] behaviors. The algorithm here is designed to run across multiple public servers where it creates races among
all servers to test a routes NAT. The result is you end up with
the fastest possible determination of NAT behaviors while also
building in safe-guards against packet-loss, inconsistent results, misconfigurations, and slow network conditions.
"""

import time
from .settings import *
from .ip_range import *
from .stun_client import *

# Constants for a NAT test.
NAT_TEST_NO = 5
NAT_TEST_TIMEOUT = 0.5

# STUN payload to send, Send IP, send port, reply IP, reply port
# Shows order of RFC 3489 NAT enumeration sets.
NAT_TEST_SCHEMA = [
    # Detects: open NAT.
    ["", "primary", "primary", "primary", "primary"],

    # Detects: full cone NAT.
    # Change both reply IP and port.
    [changeRequest, "primary", "primary", "secondary", "secondary"],

    # Detects: non-symmetric NAT.
    ["", "secondary", "primary", "secondary", "primary"],

    # Detects: between restrict and port restrict.
    # Change only the reply port.
    [changePortRequest, "secondary", "primary", "secondary", "secondary"],
]

def filter_nat_servers(nat_servers):
    out = []

    def find_duplicates(hey, cmp_ipr=None):
        ip_types = ["primary", "secondary"]
        for entry in hey:
            for ip_type in ip_types:
                entry_ip = entry[ip_type]["ip"]
                if entry_ip is None:
                    continue
                else:
                    entry_ipr = IPRange(entry_ip)

                if cmp_ipr is not None:
                    if entry_ipr == cmp_ipr:
                        return True
                else:
                    if not find_duplicates(out, entry_ipr):
                        out.append(entry)

        return False
            
    find_duplicates(nat_servers)
    return out

async def new_stun_server_format(af):
    servers = []
    for index in range(0, len(STUND_SERVERS[af])):
        route = i.route(af)
        stun_addr = await Address(
            STUND_SERVERS[af][index][0],
            STUND_SERVERS[af][index][1],
            route
        )

        out = await do_nat_test(
            stun_addr=stun_addr,
            interface=i,
            af=af,
            proto=TCP,
            group="change"
        )

        print(out)

        if out is None or isinstance(out, tuple):
            continue
    
        svr = {
            "host": STUND_SERVERS[af][index][0],
            "primary": {
                "ip": stun_addr.tup[0],
                "port": stun_addr.tup[1]
            },
            "secondary": {
                "ip": out["cip"],
                "port": out["cport"]
            }
        }

        servers.append(svr)


    print(servers)

async def nat_test_exec(dest_addr, reply_addr, payload, pipe, q, test_coro):
    # Expect messages from this reply_addr.
    tran_info = tran_info_patterns(reply_addr.tup)
    pipe.subscribe(tran_info[0:2])
    conf = dict_merge(STUN_CONF, {
        "packet_retry": 1,
        "recv_timeout": NAT_TEST_TIMEOUT
    })

    # Do first NAT test.
    ret, _ = await stun_sub_test(
        "running nat test",
        dest_addr,
        pipe.route.interface,
        pipe.route.af,
        UDP,
        pipe.sock.getsockname()[1],
        reply_addr,
        payload,
        pipe=pipe,
        tran_info=tran_info,
        conf=conf
    )

    # Valid reply.
    if ret is not None and not isinstance(ret, tuple):
        if ret["resp"]:
            q.append(ret)
            return await test_coro(ret, pipe)

    return None

async def nat_test_workers(pipe, q, test_index, test_coro, servers):
    # Make list of coroutines to do this NAT tests.
    workers = []
    for server_no in range(0, min(NAT_TEST_NO, len(servers))):
        async def worker(server_no):
            # Packets will go to this destination.
            # Send to, expect from.
            addrs = [] 
            for x in range(0, 2):
                # Determine which fields to use for IP and port.
                schema = NAT_TEST_SCHEMA[test_index][(x * 2) + 1:(x * 2) + 3]
                ip_type = schema[0]
                port_type = schema[1]

                # Resolve IP and port as an Address.
                addrs.append(
                    await Address(
                        servers[server_no][ip_type]["ip"],
                        servers[server_no][port_type]["port"],
                        pipe.route
                    )
                )

            # Run the test and return the results.
            payload = NAT_TEST_SCHEMA[test_index][0]
            return await nat_test_exec(
                # Send to and expect from.
                addrs[0],
                addrs[1],

                # Type of STUN request to send.
                payload,

                # Pipe to reuse for UDP.
                pipe,

                # Async queue to store the results.
                q,

                # Test-specific code.
                test_coro
            )

        workers.append(worker(server_no))

    return workers

"""
If a NAT uses the same 'mapping' (external IP and port) given
the same internal (IP and port) even when destinations are
different then it's considered non-symmetric. The software
proceeds to determine the exact conditions for which mappings
can be reused when using the same bind tuples.
"""
def non_symmetric_check(q_list):
    # Test 1 and 3.
    q1 = q_list[0]
    q3 = q_list[2]

    # Not enough data to know.
    if not len(q1) or not len(q3):
        return False

    # NAT reuses mappings given same internal (ip and port)
    port_check = q1[0]['rport'] == q3[0]['rport']
    ip_check = ip_f(q1[0]['rip']) == ip_f(q3[0]['rip'])
    if port_check and ip_check:
        return True

    # Otherwise return False.
    return False

"""
If there's no replies in any of the NAT test lists then
assume that this means there's a firewall and return False.
"""
def no_stun_resp_check(q_list):
    for i in range(0, 4):
        if len(q_list[i]):
            return False
        
    return True

async def fast_nat_test(pipe, test_servers, timeout=NAT_TEST_TIMEOUT):
    # Ensure all primary and secondary IPs are unique
    test_servers = filter_nat_servers(test_servers)

    # Store STUN request results here.
    # n = index of test e.g. [0] = test 1.
    q_list = [[], [], [], []]
    q_list.append(SYMMETRIC_NAT)

    # Open NAT type.
    async def test_one(ret, test_pipe):
        source_ip = test_pipe.route.bind_ip()
        if ip_f(ret['rip']) == ip_f(source_ip):
            return OPEN_INTERNET

    # Full cone NAT.
    async def test_two(ret, test_pipe):
        # Test 2 may arrive before test 1.
        # In this case: test 1 takes priority over test 2.
        return test_one(ret, test_pipe) or FULL_CONE
    
    # Whitelist of dest (IP and port).
    async def test_three(ret, test_pipe):
        if non_symmetric_check(q_list):
            q_list[4] = RESTRICT_PORT_NAT

    # Whitelist of dest (IP).
    async def test_four(ret, test_pipe):
        return RESTRICT_NAT
    
    """
    All tests in sub_test_a are tried then sub_tests_b.
    Both sub test lists can't be run concurrently
    due to how NATs function with white listing.
    """
    test_index = 0
    for sub_test in [[test_one, test_two], [test_three, test_four]]:
        # Get a list of workers for first two NAT tests.
        workers = []
        for test_coro in sub_test:
            # Build list of coroutines to run these NAT tests.
            # Test funcs are run on receiving a STUN response.
            workers += await nat_test_workers(
                pipe,
                q_list[test_index],
                test_index,
                test_coro,
                test_servers, 
            )

            # Keep track of test offset.
            test_index += 1

        # Run NAT sub tests.
        try:
            # First result in or timeout.
            for task in asyncio.as_completed(workers, timeout=timeout):
                ret = await task
                if ret is not None:
                    return ret
        except asyncio.TimeoutError:
            continue

    # All tests timed out.
    # Determine return value.
    if no_stun_resp_check(q_list):
        return BLOCKED_NAT
    else:
        # Symmetric NAT or RESTRICT_PORT_NAT.
        return q_list[-1] 

async def nat_test_main():
    from .interface import Interface, init_p2pd

    # Load internal interface details.
    t1 = timestamp(1)
    netifaces = await init_p2pd()
    t2 = timestamp(1)
    duration = t2 - t1
    print(f"init_p2pd() = {duration}")

    # Start interface time.
    i = await Interface("ens33", netifaces=netifaces) # ens37
    t1 = timestamp(1)
    nat = await i.load_nat()
    print(nat)
    t2 = timestamp(1)
    duration = t2 - t1
    print(f"Interface() load_nat = {duration}")
    await asyncio.sleep(NAT_TEST_NO)
    return


    # Use same pipe with multiplexing for reuse tests.
    #t1 = timestamp(1)
    af = IP4
    route = await i.route(af).bind(0)
    pipe = await pipe_open(UDP, route=route, conf=STUN_CONF)
    assert(pipe is not None)

    # Determine NAT type.
    t1 = timestamp(1)
    servers = STUND_SERVERS[af]
    nat_type = await fast_nat_test(pipe, servers)
    print(nat_type)

    # How long the NAT type took.
    t2 = timestamp(1) - t1
    print(f"nat time = {t2}")
    await pipe.close()
    # 0.8

    # Wait for all lagging tests to end.
    await asyncio.sleep(NAT_TEST_TIMEOUT)

if __name__ == "__main__":
    async_test(nat_test_main)