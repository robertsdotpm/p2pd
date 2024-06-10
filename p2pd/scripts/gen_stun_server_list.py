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
import pprint 



def get_existing_stun_servers(serv_path="stun_servers.txt"):
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

                    break

    # Add in details from the 
    serv_addr_set = set()
    fp = open(serv_path, 'r')
    lines = fp.readlines()
    for line in lines:
        line = line.replace('"', "")

        try:
            ip, port = line.split(":")
            port = port.strip()
            port = int(port)
        except:
            ip = line
            port = 3478

        ip = ip.strip()
        serv_addr_set.add((ip, port))

    return serv_addr_set

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
    lax = 0 if proto == UDP else 1


    error = stun_check_reply(dest_addr, nat_info, lax)
    if error:
        log("> STUN valid servers ... first reply error = %s." % (error))
        return None

    # Validate change.
    if recurse:
        change_ret = await validate_stun_server(af, ret["cip"], ret["cport"], proto, interface, recurse=False)
        if proto == UDP:
            if change_ret is None:
                return
        else:
            if change_ret is None:
                ret["cip"] = ret["cport"] = None

    if ret["sip"] is None:
        return None

    await pipe.close()    
    return [af, host, ret["sip"], ret["sport"], ret["cip"], ret["cport"], proto]

async def workspace():
    i = await Interface().start()

    existing_addrs = get_existing_stun_servers()
    existing_addrs = list(existing_addrs)
    #existing_addrs = [("stunserver.stunprotocol.org", 3478)]
    

    

    """
    # 4d64:57a5 this doesnt work for TCP
    r = await i.route(IP6).bind()

    a = await Address("stunserver.stunprotocol.org", 3478, r)
    print(a.tup)

    p = await init_pipe(a, i, IP6, TCP, 0, r)
    print(p)

    r2 = await i.route(IP6).bind()
    print(r2.af)

    addr = await Address("google.com", 80, r)
    curl = WebCurl(addr, do_close=0)
    resp = await curl.vars().get("/")
    print(resp.out)
    return
    

    print(STUN_CONF)
    ret = await stun_sub_test("", a, i, IP6, TCP, 0, a, local_addr=r)
    print(ret)

    
    it seems that TCP bind cant use all the interface addresses
    that UDP bind can?

    The interface code should put routes in a deterministic order.




    s = STUNClient(i, proto=TCP)
    out = await s.get_wan_ip()
    print(out)
    return
    """

    tasks = []
    for proto in [UDP, TCP]:
        for af in VALID_AFS:
            for serv_addr in existing_addrs:
                host, port = serv_addr
                task = validate_stun_server(af, host, port, proto, i)
                tasks.append(task)

    results = []
    for task in tasks:
        result = await task
        print(result)
        results.append(result)
    
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

    # Todo: filter out alias domains.

    stund_servers = pprint.pformat(stund_servers)
    stunt_servers = pprint.pformat(stunt_servers)

    print(stund_servers)
    print()
    print()
    print()
    print(stunt_servers)

    with open("stund.txt", "w") as fp1:
        fp1.truncate()
        fp1.write(str(stund_servers))

    with open("stunt.txt", "w") as fp2:
        fp2.truncate()
        fp2.write(str(stunt_servers))


async_test(workspace)