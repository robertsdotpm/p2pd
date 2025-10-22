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

Pythons get addrinfo just calls the regular sync socket
function in an executor which is probably capped at cpu core no
thats probably why the performance is terrible for high
concurrency

"""
from concurrent.futures import ThreadPoolExecutor


import platform
import trio

import dns.message
import dns.asyncquery
import dns.asyncresolver

from p2pd import *

if platform.system() == "Windows":
    loop = asyncio.ProactorEventLoop()
    asyncio.set_event_loop(loop)


TASK_TIMEOUT = 60
ENABLE_PROTOS = [TCP, UDP]
ENABLE_AFS = [IP4, IP6]

STUN_CONF = dict_child({
    # Retry N times on reply timeout.
    "packet_retry": 3,

    # Retry N times on invalid address.
    "addr_retry": 2,

    # Seconds to use for a DNS request before timeout exception.
    "dns_timeout": 20, # 2

    "recv_config": 5,

    "con_timeout": 10,

    # Retry no -- if an individual call fails how
    # many times to retry the whole thing.
    "retry_no": 3,
}, NET_CONF)

def dns_get_ip(r):
    """
    if not len(r.answer):
        r.answer = [r.answer]
    """
    for i in range(0, len(r.answer)):
        answer = r.answer[i]
        if answer.rdtype.value in [28, 1]:
            return str(answer.to_rdataset()[0])



def get_existing_stun_servers(serv_path="stun_servers.txt"):
    serv_addr_set = set()
    for serv_dict in [STUN_CHANGE_SERVERS, STUN_MAP_SERVERS]:
        for proto in [UDP, TCP]:
            for af in VALID_AFS:
                for serv_info in serv_dict[proto][af]:
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

async def validate_stun_server(af, host, port, proto, interface, mode, timeout, recurse=True):
    # Attempt to resolve STUN server address.
    route = interface.route(af)
    try:
        ip = None
        try:
            ipr = IPRange(host, cidr=af_to_cidr(af))
            ip = host
        except:
            pass

        if ip is None:
            async def res_name():
                ip = None
                if af == IP4:
                    q = dns.message.make_query(host, "A")
                    r = await dns.asyncquery.udp(q, "8.8.8.8")
                    ip = dns_get_ip(r)
                if af == IP6:
                    q = dns.message.make_query(host, "AAAA")
                    r = await dns.asyncquery.udp(q, "2001:4860:4860::8888")
                    ip = dns_get_ip(r)

                return ip
                
            ip = await asyncio.wait_for(res_name(), STUN_CONF["dns_timeout"])
            if ip is None:
                return None
        else:
            ip = host
        
        dest = (
            ip,
            port,
        )
        if af == IP6:
            dest.tup = (ip, port, 0, 0)
        else:
            dest.tup = (ip, port)

        dest.af = dest.chose = af
        dest.target = ip
        dest.afs_found = [af]
        dest.is_loopback = False
        dest.is_private = False
        dest.is_public = True
        dest.resolved = True
        
    except:
        log_exception()
        log(f"val stun server addr fail: {host}:{port}")
        return None
    
    """
    Some 'public' STUN servers like to point to private
    addresses. This could be dangerous.
    """
    ipr = IPRange(dest.tup[0], cidr=af_to_cidr(af))
    if ipr.is_private:
        log(f"{af} {host} {recurse} is private")
        return None

    # New pipe used for the req.
    stun_client = STUNClient(dest, proto, mode, conf=STUN_CONF)
    try:
        reply = await stun_client.get_stun_reply()
    except:
        log_exception()
        log(f"{af} {host} {proto} {mode} get reply {recurse} none")
        return None
    
    reply = validate_stun_reply(reply, mode)
    if reply is None:
        return
    # Cleanup.
    if hasattr(reply, "pipe"):
        await reply.pipe.close()  

    # Validate change server reply.
    ctup = (None, None)
    if mode == RFC3489:
        if recurse and hasattr(reply, "ctup"):
            try:
                # Change IP different from reply IP.
                if reply.stup[0] == reply.ctup[0]:
                    log(f'ctup bad {to_h(reply.txn_id)}: bad {reply.ctup[0]} 1')
                    return None
                
                # Change port different from reply port.
                if reply.stup[1] == reply.ctup[1]:
                    log(f'ctup bad {to_h(reply.txn_id)}: bad {reply.ctup[0]} 2')
                    return None


                creply = await validate_stun_server(
                    af,
                    reply.ctup[0],
                    reply.ctup[1],
                    proto,

                    interface,
                    mode,
                    timeout,
                    recurse=False # Avoid infinite loop.
                )
            except:
                log(f"vaid stun recurse failed {af} {host}")
                log_exception()
            if creply is not None:
                ctup = reply.ctup
            else:
                log(f"{af} {host} {reply.ctup} ctup get reply {recurse} none")

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
    loop = asyncio.get_running_loop()

    # Set the default executor
    #loop.set_default_executor(ThreadPoolExecutor(150))

    
    q = dns.message.make_query('google.com', "AAAA")
    r = await dns.asyncquery.udp(q, "2001:4860:4860::8888")

    print(dir(r.answer.count))
    #print(r.answer[1])
    

    #return


    ip = r.answer[0].to_rdataset()[0]
    print(ip)
    print(dir(r.answer[0].rdtype))
    print(r.answer[0].rdtype.value)


    print(ip)
    
    
    
    i = await Interface().start()




    """
    dest = await Address("stun.voip.blackberry.com", 3478, i.route(IP4))
    sc = STUNClient(dest, mode=RFC5389, proto=TCP)
    reply = await sc.get_mapping()
    """


    # Get a big list of STUN server tuples.
    existing_addrs = get_existing_stun_servers()
    existing_addrs = list(existing_addrs)
    #existing_addrs = [("stun.zentauron.de", 3478)]
    #existing_addrs = [("34.74.124.204", 3478)] stun.moonlight-stream.org
    #existing_addrs = [("stunserver.stunprotocol.org", 3478)]
    #existing_addrs = existing_addrs[:100]
    #existing_addrs = [("stun.l.google.com", 19302)]
    print(len(STUND_SERVERS[IP4]))
    print(len(existing_addrs))
        
    # 2 * 2 * 2 per server
    # maybe do all these tests for each server in a batch
    results = []
    tasks = []
    task_timeout = 10   
    for serv_addr in existing_addrs:
        #tasks = []
        for mode in [RFC3489, RFC5389]:
            for proto in ENABLE_PROTOS:
                for af in ENABLE_AFS:
                    host, port = serv_addr

                    task = create_task(
                        async_wrap_errors(
                            validate_stun_server(af, host, port, proto, i, mode, task_timeout-2),
                            timeout=10
                        )
                    )
                    

                    tasks.append(task)

        #out = await asyncio.gather(*tasks)
        #print(out)
        #results += out

    results = await asyncio.gather(*tasks)

    """
    todo: why doesn't concurrency work? Is it a problem with getaddrinfo?
    Is the library to blame? I think this would yield interesting insights
    """
    # Validate stun server.
    #results = []
    """
    for task in tasks:
        result = await task
        print(result)
        results.append(result)
    """

    """
    c = 8
    while len(tasks):
        sub_tasks = tasks[:c]
        tasks = tasks[c:]
        out = await asyncio.gather(*sub_tasks)
        print(out)
        results += out
    """


    #results = await asyncio.gather(*tasks)
    
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

        #print(result)
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

        """
        All change servers are also map servers but
        map servers aren't all change servers.
        """
        if serv_list == stun_change_servers:
            stun_map_servers[proto][af].append(entry)

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
                        if ip is None:
                            continue
                        
                        if ip in seen_ips:
                            add_this = False

                        seen_ips.add(ip)

                    if add_this:
                        clean_index[af].append(serv_info)


            serv_index[proto] = clean_index

    # Indication if test was right.
    print(len(stun_change_servers[UDP][IP4]))
    print(len(stun_map_servers[UDP][IP4]))

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