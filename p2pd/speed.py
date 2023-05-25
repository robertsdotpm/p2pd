import time
from .interface import *
from .stun_client import *

NAT_TEST_NO = 5
NAT_TEST_TIMEOUT = 2

stun_new = {
    IP4: [
        {
            "host": "stun.voipcheap.co.uk",
            "primary": {"ip": "77.72.169.211", "port": 3478},
            "secondary": {"ip": "77.72.169.210", "port": 3479},
        },
        {
            "host": "stunserver.stunprotocol.org",
            "primary": {"ip": "3.132.228.249", "port": 3478},
            "secondary": {"ip": "3.135.212.85", "port": 3479},
        },
        {
            "host": "stun.usfamily.net",
            "primary": {"ip": "64.131.63.216", "port": 3478},
            "secondary": {"ip": "64.131.63.240", "port": 3479},
        },
        {
            "host": "stun.ozekiphone.com",
            "primary": {"ip": "216.93.246.18", "port": 3478},
            "secondary": {"ip": "216.93.246.15", "port": 3479},
        },
        {
            "host": "stun.voipwise.com",
            "primary": {"ip": "77.72.169.213", "port": 3478},
            "secondary": {"ip": "77.72.169.212", "port": 3479},
        },
        {
            "host": "stun.mit.de",
            "primary": {"ip": "62.96.96.137", "port": 3478},
            "secondary": {"ip": "62.96.96.138", "port": 3479},
        },
        {
            "host": "stun.hot-chilli.net",
            "primary": {"ip": "49.12.125.53", "port": 3478},
            "secondary": {"ip": "49.12.125.24", "port": 3479},
        },
        {
            "host": "stun.counterpath.com",
            "primary": {"ip": "216.93.246.18", "port": 3478},
            "secondary": {"ip": "216.93.246.15", "port": 3479},
        },
        {
            "host": "stun.cheapvoip.com",
            "primary": {"ip": "77.72.169.212", "port": 3478},
            "secondary": {"ip": "77.72.169.213", "port": 3479},
        },
        {
            "host": "webrtc.free-solutions.org",
            "primary": {"ip": "94.103.99.223", "port": 3478},
            "secondary": {"ip": "94.103.99.224", "port": 3479},
        },
        {
            "host": "stun.t-online.de",
            "primary": {"ip": "217.0.12.17", "port": 3478},
            "secondary": {"ip": "217.0.12.18", "port": 3479},
        },
        {
            "host": "stun.sipgate.net",
            "primary": {"ip": "217.10.68.152", "port": 3478},
            "secondary": {"ip": "217.116.122.136", "port": 3479},
        },
        {
            "host": "stun.voip.aebc.com",
            "primary": {"ip": "66.51.128.11", "port": 3478},
            "secondary": {"ip": "66.51.128.12", "port": 3479},
        },
        {
            "host": "stun.callwithus.com",
            "primary": {"ip": "158.69.57.20", "port": 3478},
            "secondary": {"ip": "149.56.23.84", "port": 3479},
        },
        {
            "host": "stun.counterpath.net",
            "primary": {"ip": "216.93.246.18", "port": 3478},
            "secondary": {"ip": "216.93.246.15", "port": 3479},
        },
        {
            "host": "stun.ekiga.net",
            "primary": {"ip": "216.93.246.18", "port": 3478},
            "secondary": {"ip": "216.93.246.15", "port": 3479},
        },
        {
            "host": "stun.internetcalls.com",
            "primary": {"ip": "77.72.169.212", "port": 3478},
            "secondary": {"ip": "77.72.169.213", "port": 3479},
        },
        {
            "host": "stun.voipbuster.com",
            "primary": {"ip": "77.72.169.212", "port": 3478},
            "secondary": {"ip": "77.72.169.213", "port": 3479},
        },
        {
            "host": "stun.12voip.com",
            "primary": {"ip": "77.72.169.212", "port": 3478},
            "secondary": {"ip": "77.72.169.213", "port": 3479},
        },
        {
            "host": "stun.freecall.com",
            "primary": {"ip": "77.72.169.211", "port": 3478},
            "secondary": {"ip": "77.72.169.210", "port": 3479},
        },
        {
            "host": "stun.nexxtmobile.de",
            "primary": {"ip": "5.9.87.18", "port": 3478},
            "secondary": {"ip": "136.243.205.11", "port": 3479},
        },
        {
            "host": "stun.siptrunk.com",
            "primary": {"ip": "23.21.92.55", "port": 3478},
            "secondary": {"ip": "34.205.214.84", "port": 3479},
        },
    ],
    IP6: []
}

"""
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

async def do_nat_test(dest_addr, reply_addr, payload, pipe, q, test_coro):
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

    print(f"dest addr = {dest_addr.tup}")
    print(f"reply addr = {reply_addr.tup}") 
    print(f"payload = {payload}")

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
            if test_coro is not None:
                return await test_coro(ret, pipe)
            else:
                return ret

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

            return await do_nat_test(
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

async def fast_nat_test(pipe, test_servers):
    # Shuffle STUN servers.
    servers = copy.deepcopy(test_servers[pipe.route.af])
    #random.shuffle(servers)

    # Store STUN request results here.
    # n = index of test e.g. [0] = test 1.
    q_list = [[], [], [], []]
    q_list.append(SYMMETRIC_NAT)

    # Open NAT type.
    async def test_one(ret, test_pipe):
        source_ip = test_pipe.route.bind_ip()
        if ip_f(ret['rip']) == ip_f(source_ip):
            return OPEN_INTERNET
        return None

    # Full cone NAT.
    async def test_two(ret, test_pipe):
        return FULL_CONE
    
    # Get a list of workers for first two NAT tests.
    main_workers = []
    for test_info in [[0, test_one, 0], [1, test_two, 0]]:
        # Build list of coroutines to run these NAT tests.
        test_index, test_coro, test_delay = test_info
        workers = await nat_test_workers(
            pipe,
            q_list[test_index],
            test_index,
            test_coro,
            servers, 
        )

        # Delayed start.
        if test_delay:
            # Wrap the coroutine to delay it's main execution.
            async def worker(delay, coro):
                #await asyncio.sleep(delay)
                return await coro
            
            # El8 compact list comprehension.
            workers = [worker(test_delay, coro) for coro in workers]

        # Add to list to run.
        # print(workers)
        main_workers += workers

    """
    x = await main_workers[0]
    print(x)
    print(q_list)
    await asyncio.sleep(2)
    y = await main_workers[1]
    print(y)
    print(q_list)
    return
    """

    # Run NAT tests.
    log("Main nat tests starting.")
    try:
        # iterate over awaitables with a timeout
        for task in asyncio.as_completed(main_workers, timeout=2):
            # get the next result
            ret = await task
            if ret is not None:
                return ret
            
    except asyncio.TimeoutError:
        log("Extended NAT tests starting.")

    # Full cone NAT.
    async def test_three(ret, test_pipe):
        if non_symmetric_check(q_list):
            q_list[4] = RESTRICT_PORT_NAT
        return None

    # Full cone NAT.
    async def test_four(ret, test_pipe):
        if non_symmetric_check(q_list):
            return RESTRICT_NAT

        return None
    
    # Get a list of workers for last two NAT tests.
    extra_workers = []
    for test_info in [[2, test_three], [3, test_four]]:
        test_index, test_coro = test_info
        extra_workers += await nat_test_workers(
            pipe,
            q_list[test_index],
            test_index,
            test_coro,
            servers
        )

    # Process results for extended tests.
    try:
        # iterate over awaitables with a timeout
        for task in asyncio.as_completed(extra_workers, timeout=2):
            # get the next result
            ret = await task
            if ret is not None:
                return ret
    except asyncio.TimeoutError:
        log("Extended NAT test timeout.")

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
    i = await Interface("ens37", netifaces=netifaces) # ens37
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
                af=af
            )

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


    pass

if __name__ == "__main__":
    async_test(main)