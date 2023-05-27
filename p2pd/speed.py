import time
from .interface import *
from .stun_client import *
from .ip_range import *

NAT_TEST_NO = 5
NAT_TEST_TIMEOUT = 0.5

"""
Does multiple sub tests to determine NAT type.
It will differ dest ips, reply ips and/or reply ports.
Reply success or failure + external ports reported
by servers are used to infer the type of NAT.
Note: complete resolution of NAT type is only
possible with proto = SOCK_DGRAM. This is because
the router doesn't just allow inbound connects
that either haven't been forwarded or
contacted specifically.

NOTE: my concurrent optimization here with tests 2 - 4
seem in error since tests 3 and 4 white lists t2 change ip.
Stupid mistake to miss. maybe I dont have any full cone nats?
"""

"""
Actually duplicate prevetion in the ips is important
because if the same sites (with dif prim and secondary are visited) 
then it triggers full cone artifically

labnet = 4 ()
nbn = 5 () (success with 5 test no)

not so sure about full cone
"""

"""
Regarding TEST[2]:

Original pystun3 uses secondary, secondary here which is a bug.

The dest (ip AND port) needs to be 'whitelisted' in a port restrict NAT
so using secondary, secondary meant that test 4 would also succeed on a port restrict NAT since it's reply tup had already been whitelisted
in test 3. A reply is meant to only occur on a restrict NAT.

Requirements: your external IP and mapping stay the same when
the same internal source IP and port are used.
"""

# STUN payload to send, Send IP, send port, reply IP, reply port
NAT_TEST_SCHEMA = [
    # Detects: open NAT.
    ["", "primary", "primary", "primary", "primary"],

    # Detects: full cone NAT.
    [changeRequest, "primary", "primary", "secondary", "secondary"],

    # Detects: non-symmetric NAT.
    ["", "secondary", "primary", "secondary", "primary"],

    # Detects: between restrict and port restrict.
    [changePortRequest, "secondary", "primary", "secondary", "secondary"],
]

def filter_nat_servers(nat_servers):
    out = []

    def find_duplicates(hey, cmp_ipr=None):
        ip_types = ["primary", "secondary"]
        for entry in hey:
            for ip_type in ip_types:
                entry_ip = entry[ip_type]
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



async def nat_test_exec(dest_addr, reply_addr, payload, pipe, q, test_coro):
    tran_info = tran_info_patterns(reply_addr.tup)
    pipe.subscribe(tran_info[0:2])

    # Adding that fixed the bug but why?
    # Maybe prevents one coro hogging the exec slot.
    conf = dict_merge(STUN_CONF, {
            "packet_retry": 6,
            "retry_no": 6,
            "recv_timeout": 2
        }
    )

    #print(f"dest addr = {dest_addr.tup}")
    #print(f"reply addr = {reply_addr.tup}") 
    #print(f"payload = {payload}")

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
        conf=STUN_CONF
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

                print(f"test no = {test_index} schema = {schema} server no = {server_no} x = {x}")



                # Resolve IP and port as an Address.
                addrs.append(
                    await Address(
                        servers[server_no][ip_type]["ip"],
                        servers[server_no][port_type]["port"],
                        pipe.route
                    )
                )

                #print(f"{addrs[x].tup}")

            print(f"{addrs[0].tup}")
            print(f"{addrs[1].tup}")

            await Address(servers[server_no]["host"], 3478, pipe.route)

            # Run the test and return the results.
            payload = NAT_TEST_SCHEMA[test_index][0]
            print(payload)

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
    # Store STUN request results here.
    # n = index of test e.g. [0] = test 1.
    q_list = [[], [], [], []]
    q_list.append(SYMMETRIC_NAT)

    # Open NAT type.
    async def test_one(ret, test_pipe):
        source_ip = test_pipe.route.bind_ip()
        if ip_f(ret['rip']) == ip_f(source_ip):
            return OPEN_INTERNET

    # Full cone NATl
    async def test_two(ret, test_pipe):
        return FULL_CONE
    
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
    sub_tests_a = [test_one, test_two]
    sub_tests_b = [test_three, test_four]
    for sub_test in [sub_tests_a, sub_tests_b]:
        # Get a list of workers for first two NAT tests.
        workers = []
        for test_coro in sub_test:
            # Build list of coroutines to run these NAT tests.
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

async def main():
    # Load internal interface details.
    t1 = timestamp(1)
    netifaces = await init_p2pd()
    t2 = timestamp(1)
    duration = t2 - t1
    print(f"init_p2pd() = {duration}")

    # Start interface time.
    t1 = timestamp(1)
    i = await Interface("ens33", netifaces=netifaces) # ens37
    t2 = timestamp(1)
    duration = t2 - t1
    print(f"Interface().start() = {duration}")

    # Load nat ->> bottleneck
    """
    t1 = timestamp(1)
    i = await i.load_nat()
    t2 = timestamp(1)
    duration = t2 - t1
    print(f"i.load_nat() = {duration}")
    """
    

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

    await new_stun_server_format(IP4)
    return


    # Use same pipe with multiplexing for reuse tests.
    af = IP4
    route = await i.route(af).bind(0)
    conf = dict_merge(STUN_CONF, {"reuse_addr": True})
    pipe = await pipe_open(UDP, route=route, conf=STUN_CONF)
    assert(pipe is not None)

    t1 = timestamp()

    """
    send_addr = await Address(
        stun_new[af][0]["primary"]["ip"],
        stun_new[af][0]["primary"]["port"],
        route
    )

    out = await do_nat_test(
        # Send to and expect from.
        send_addr,
        send_addr,

        # Type of STUN request to send.
        "",

        # Pipe to reuse for UDP.
        pipe,

        # Async queue to store the results.
        [],

        # Test-specific code.
        None
    )
    print(out)
    """

    t1 = timestamp()

    """
    change_addr = await Address(
        stun_new[af][0]["secondary"]["ip"],
        stun_new[af][0]["secondary"]["port"],
        route
    )

    out = await do_nat_test(
        # Send to and expect from.
        send_addr,
        change_addr,

        # Type of STUN request to send.
        changeRequest,

        # Pipe to reuse for UDP.
        pipe,

        # Async queue to store the results.
        [],

        # Test-specific code.
        None
    )
    print(out)
    """


    nat_type = await fast_nat_test(pipe, stun_new)
    print(nat_type)

    t2 = timestamp() - t1
    print(f"nat time = {t2}")
    await pipe.close()


    await asyncio.sleep(5)


    pass

if __name__ == "__main__":
    async_test(main)