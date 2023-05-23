import time
from .interface import *
from .stun_client import *

NAT_TEST_NO = 5

stun_new = {
    IP4: [
        {
            "host": "stunserver.stunprotocol.org",
            "primary": {"ip": "3.132.228.249", "port": 3478},
            "secondary": {"ip": "3.135.212.85", "port": 3479},
        },
        {
            "host": "stun.voipcheap.co.uk",
            "primary": {"ip": "77.72.169.211", "port": 3478},
            "secondary": {"ip": "77.72.169.210", "port": 3479},
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

# STUN payload to send, Send IP, send port, reply IP, reply port
NAT_TEST_SCHEMA = [
    [               "", "primary", "primary", "primary", "primary"],
    [    changeRequest, "primary", "primary", "secondary", "secondary"],
    [               "", "secondary", "primary", "secondary", "primary"],
    [changePortRequest, "secondary", "primary", "secondary", "secondary"],
]

# TODO: Different conf here?
async def do_nat_test(dest_addr, reply_addr, payload, pipe, q, test_coro):
    # Only accept messages from reply_addr.
    tran_info = tran_info_patterns(reply_addr.tup)
    pipe.subscribe(tran_info[0:2])

    # Do first NAT test.
    ret, _ = await stun_sub_test(
        "running nat test",
        dest_addr,
        pipe.route.interface,
        pipe.af,
        UDP,
        0,
        reply_addr,
        payload,
        pipe=pipe,
        tran_info=tran_info,
        conf=STUN_CONF
    )

    # Valid reply.
    out = None
    if ret is not None and isinstance(ret, tuple):
        out = await test_coro(ret, pipe)
        await q.put(out)
    else:
        await asyncio.sleep(60)

    return out

async def nat_test_workers(pipe, q_list, test_index, test_coro, test_servers):
    servers = copy.deepcopy(test_servers[pipe.af])
    servers = servers.shuffle()
    for server_no in range(0, NAT_TEST_NO):
        async def worker():
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
            return await do_nat_test(
                # Send to and expect from.
                **addrs,

                # Type of STUN request to send.
                payload,

                # Pipe to reuse for UDP.
                pipe,

                # Async queue to store the results.
                q_list[test_index],

                # Test-specific code.
                test_coro
            )

        return worker()

def non_symmetric_check(q_list):
    # TODO: cmp 1 and 3
    pass

async def fast_nat_test(pipe, test_servers=stun_new):
    # Store STUN request results here.
    # n = index of test e.g. [0] = test 1.
    q_list = [asyncio.Queue()] * 4

    # Open NAT type.
    async def test_one(ret, test_pipe):
        source_ip = test_pipe.route.bind_ip()
        if ip_f(ret['rip']) == ip_f(source_ip):
            return OPEN_INTERNET
        else:
            await asyncio.sleep(60)

    # Full cone NAT.
    async def test_two(ret, test_pipe):
        return FULL_CONE
    
    # Get a list of workers for first two NAT tests.
    main_workers = []
    for test_info in [[0, test_one], [1, test_two]]:
        test_index, test_coro = test_info
        main_workers += await nat_test_workers(
            pipe,
            q_list,
            test_index,
            test_coro,
            test_servers, 
        )

    # Continue to extended tests.
    try:
        # iterate over awaitables with a timeout
        for task in asyncio.as_completed(main_workers, timeout=2):
            # get the next result
            return await task
    except asyncio.TimeoutError:
        log("Extended NAT tests starting.")

    # Full cone NAT.
    timeout_ret = SYMMETRIC_NAT
    async def test_three(ret, test_pipe):
        if non_symmetric_check(q_list):
            if len(q_list) == 4:
                q_list.append(RESTRICT_PORT_NAT)

        await asyncio.sleep(60)

    # Full cone NAT.
    async def test_four(ret, test_pipe):
        if non_symmetric_check(q_list):
            return RESTRICT_NAT
        
        await asyncio.sleep(60)
    
    # Get a list of workers for last two NAT tests.
    extra_workers = []
    for test_info in [[2, test_three], [3, test_four]]:
        test_index, test_coro = test_info
        extra_workers += await nat_test_workers(
            pipe,
            q_list,
            test_index,
            test_coro,
            test_servers
        )

    # Process results for extended tests.
    try:
        # iterate over awaitables with a timeout
        for task in asyncio.as_completed(main_workers, timeout=2):
            # get the next result
            return await task
    except asyncio.TimeoutError:
        log("Extended NAT test timeout.")

        # TODO: no replies = blocked_nat

        return timeout_ret 

    
    


async def main():
    # Load internal interface details.
    t1 = timestamp(1)
    netifaces = await init_p2pd()
    t2 = timestamp(1)
    duration = t2 - t1
    print(f"init_p2pd() = {duration}")

    # Start interface time.
    t1 = timestamp(1)
    i = await Interface(netifaces=netifaces)
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
    route = await i.route(af).bind()
    pipe = await pipe_open(UDP, route=route)



    pass

if __name__ == "__main__":
    async_test(main)