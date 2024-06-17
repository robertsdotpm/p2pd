"""
I think maybe I know what the concurrency issue is:

- lets say you have a list of coroutines
- you pass them to async gather with a timeout expecting
to limit the operation until some time
- ideally: in this instance what you want to do is to
force all coroutines that dont return a result before
the timeout to return none and fail
- but instead: a single slow coroutine that doesnt finish
in time leads to timing out the entire list of results
- that makes using async gather across a list of servers
a bad idea -- it would be easy enough to write an alternative
- finally: when its combined with domain lookups to places
that dont exist or services that are no longer there it
means that you cannot possibly get results back

"""

from p2pd import *

ENABLE_PROTOS = [TCP, UDP]
ENABLE_AFS = [IP4, IP6]

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

async def validate_stun_server(af, host, port, proto, interface, mode, recurse=True):
    # Attempt to resolve STUN server address.
    route = interface.route(af)
    dest = await Address(
        host,
        port,
        route=route
    )
    if not len(dest.tup):
        return
    
    """
    Some 'public' STUN servers like to point to private
    addresses. This could be dangerous.
    """
    ipr = IPRange(dest.tup[0], cidr=af_to_cidr(af))
    if ipr.is_private:
        return

    # New pipe used for the req.
    stun_client = STUNClient(dest, proto, mode)
    try:
        reply = await stun_client.get_stun_reply()
    except:
        return None
    
    reply = validate_stun_reply(reply, mode)
    if reply is None:
        return
    
    # Validate change server reply.
    ctup = (None, None)
    if mode == RFC3489:
        if recurse:
            creply = await validate_stun_server(
                af,
                reply.ctup[0],
                reply.ctup[1],
                proto,
                interface,
                mode,
                recurse=False # Avoid infinite loop.
            )
            if creply is not None:
                ctup = reply.ctup
    
    # Cleanup.
    if hasattr(reply, "pipe"):
        await reply.pipe.close()  

    # Return all the gathered data.
    return [
        af,
        host,
        dest.tup[0],
        dest.tup[1], 
        ctup[0],
        ctup[1],
        proto,
        mode
    ]

async def workspace():
    i = await Interface().start()
    """
    dest = await Address("stun.voip.blackberry.com", 3478, i.route(IP4))
    sc = STUNClient(dest, mode=RFC5389, proto=TCP)
    reply = await sc.get_mapping()
    """


    # Get a big list of STUN server tuples.
    existing_addrs = get_existing_stun_servers()
    existing_addrs = list(existing_addrs)
    existing_addrs = [("stun.zentauron.de", 3478)]
    #existing_addrs = [("34.74.124.204", 3478)] stun.moonlight-stream.org
    existing_addrs = [("stun1.p2pd.net", 3478)]
        
    # 2 * 2 * 2 per server
    # maybe do all these tests for each server in a batch
    tasks = []
    for mode in [RFC3489, RFC5389]:
        for proto in ENABLE_PROTOS:
            for af in ENABLE_AFS:
                for serv_addr in existing_addrs:
                    host, port = serv_addr
                    task = validate_stun_server(af, host, port, proto, i, mode)
                    tasks.append(task)

    """
    todo: why doesn't concurrency work? Is it a problem with getaddrinfo?
    Is the library to blame? I think this would yield interesting insights
    """
    # Validate stun server.
    results = []
    for task in tasks:
        result = await task
        print(result)
        results.append(result)
    
    # Generate a list of servers for use with settings.py.
    stun_change_servers = {
        UDP: { IP4: [], IP6: [] },
        TCP: { IP4: [], IP6: [] }
    }
    stun_map_servers = {
        UDP: { IP4: [], IP6: [] },
        TCP: { IP4: [], IP6: [] }
    } 


    for result in results:
        if result is None:
            continue

        af, host, sip, sport, cip, cport, proto, mode = result

        # If it has change tup add to change list.
        if cip is not None and cport is not None:
            serv_list = stun_change_servers
        else:
            serv_list = stun_map_servers

        entry = {
            "mode": mode,
            "host": host,
            "primary": {"ip": sip, "port": sport},
            "secondary": {"ip": cip, "port": cport},
        }

        serv_list[proto][af].append(entry)

    # Filter alias domains.
    for serv_index in [stun_map_servers, stun_change_servers]:
        for proto in [UDP, TCP]:
            clean_index = {IP4: [], IP6: []}
            for af in VALID_AFS:
                seen_ips = set()
                for serv_info in serv_index[proto][af]:
                    add_this = True
                    for ip_type in ["primary", "secondary"]:
                        ip = serv_info[ip_type]["ip"]
                        if ip in seen_ips:
                            add_this = False

                        seen_ips.add(ip)

                    if add_this:
                        clean_index[af].append(serv_info)

            serv_index[proto].clear()
            serv_index[proto].update(clean_index)

    # Convert settings dict to a string.
    # Remove invalid array keys for formatting.
    def format_serv_dict(serv_dict):
        s_index = str(serv_dict)
        s_index = s_index.replace('<AddressFamily.AF_INET6: 23>', 'IP6')
        s_index = s_index.replace('<AddressFamily.AF_INET: 2>', 'IP4')
        s_index = s_index.replace('<SocketKind.SOCK_STREAM: 1>', 'TCP')
        s_index = s_index.replace('<SocketKind.SOCK_DGRAM: 2>', 'UDP')
        return s_index

    # Display results.
    stun_change_servers = format_serv_dict(stun_change_servers)
    stun_map_servers = format_serv_dict(stun_map_servers)
    print(stun_change_servers)
    print()
    print()
    print()
    print(stun_map_servers)

    # Record results.
    with open("stun_change.txt", "w") as fp1:
        fp1.truncate()
        fp1.write(str(stun_change_servers))

    with open("stun_map.txt", "w") as fp2:
        fp2.truncate()
        fp2.write(str(stun_map_servers))


async_test(workspace)