"""
I've just had TCP stun stop working despite all network tests
passing. Then when I opened wireshark the next time it worked.
Now wireshark is closed and it still works? Is this coincidence
or did wireshark make a change to the interface / firewalls and
that ended up fixing the code?

Sounds like your responses are send in a way that does not match you ethernet address. So when wireshark runs you get the data because you switch to promicious mode.

TCP: apparently on some platforms the routing table rules can choose
a different source IP even if you explicitly bind.
there has to be a way around this "strong host model" ensures it uses the interfaces preferred IP? well for windows -- i doubt it. rather than remove those routes the answer is ensure that the prefered source is always the default .route()
"""

from p2pd import *

def get_existing_stun_servers():
    serv_addr_set = set()
    for serv_dict in [STUNT_SERVERS, STUND_SERVERS]:
        for af in VALID_AFS:
            for serv_info in serv_dict[af]:
                host = serv_info["host"]
                for ip_type in ["primary", "secondary"]:
                    port = serv_info[ip_type]["port"]
                    if port is not None:
                        serv_tup = (host, port)
                        serv_addr_set.add(serv_tup)

    return list(serv_addr_set)

# UDP needs secondary and primary
# TCP doesnt

async def validate_stun_server(af, host, port, proto, interface, recurse=True):
    # Resolve host to IP.
    try:
        dest_addr = await stun_check_addr_info(
            host,
            port,
            af,
            proto,
            interface
        )
    except Exception as e:
        # Unable to find A or AAA record for address family.
        log("> STUN get_nat_type can't load A/AAA %s" % (str(e)))
        return None
    
    # If address check didn't pass skip.
    if dest_addr is None:
        log("> STUN valid servers ... dest addr is none.")
        return None
    
    # Can't connect to the STUN server.
    print(proto)
    pipe = await init_pipe(dest_addr, interface, af, proto, 0)
    if pipe is None:
        log("> STUN valid servers ... first s is none.")
        return None
    
    # Get initial port mapping.
    # A response is expected.
    tran_info = tran_info_patterns(dest_addr.tup)
    pipe.subscribe(tran_info[:2])
    ret = nat_info = await do_stun_request(
        pipe,
        dest_addr,
        tran_info
    )

    # Set source port.
    lax = 1 if proto == UDP else 0
    error = stun_check_reply(dest_addr, nat_info, lax)
    if error:
        log("> STUN valid servers ... first reply error = %s." % (error))
        return None

    # Validate change.
    if recurse:
        change_ret = await validate_stun_server(af, ret["cip"], ret["cport"], proto, interface, recurse=False)
        if proto == TCP:
            if change_ret is None:
                return
        else:
            if change_ret is None:
                ret["cip"] = ret["cport"] = None

    print(ret)

    await pipe.close()    
    return [af, host, ret["sip"], ret["sport"], ret["cip"], ret["cport"], proto]

async def workspace():
    i = await Interface().start()
    print(i)
    print(NOT_WINDOWS)

    existing_addrs = get_existing_stun_servers()
    existing_addrs = [existing_addrs[0]]
    existing_addrs = [("stunserver.stunprotocol.org", 3478)]

    
    # 4d64:57a5 this doesnt work for TCP
    r = await i.route(IP6).bind(ips="", port=0)
    a = await Address("stunserver.stunprotocol.org", 3478, r)
    print(a.tup)

    """
    p = await init_pipe(a, i, IP6, TCP, 0, r)
    print(p)

    r2 = await i.route(IP6).bind()
    print(r2.af)

    addr = await Address("google.com", 80, r)
    curl = WebCurl(addr, do_close=0)
    resp = await curl.vars().get("/")
    print(resp.out)
    return
    """

    print(STUN_CONF)
    ret = await stun_sub_test("", a, i, IP6, TCP, 0, a, local_addr=r)
    print(ret)

    """
    it seems that TCP bind cant use all the interface addresses
    that UDP bind can?

    The interface code should put routes in a deterministic order.


    """
    return

    s = STUNClient(i, proto=TCP)
    out = await s.get_wan_ip()
    print(out)
    return
    

    tasks = []
    for proto in [UDP, TCP]:
        for af in VALID_AFS:
            for serv_addr in existing_addrs:
                host, port = serv_addr
                task = validate_stun_server(af, host, port, proto, i)
                tasks.append(task)

    results = await asyncio.gather(*tasks)
    print(results)
    return

    stund_servers = {IP4: [], IP6: []}
    stunt_servers = {IP4: [], IP6: []}
    serv_lookup = {UDP: stund_servers, TCP: stunt_servers}
    for result in results:
        if result is None:
            continue

        af, host, sip, sport, cip, cport, proto = result
        serv_list = serv_lookup[proto][af]
        entry = {
            "host": host,
            "primary": {"ip": sip, "port": sport},
            "secondary": {"ip": cip, "port": cport},
        }
        serv_list.append(entry)

    print(stund_servers)
    print()
    print()
    print()
    print(stunt_servers)


async_test(workspace)