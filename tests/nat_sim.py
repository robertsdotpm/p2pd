from p2pd import *
import socket

CLIENT_IPRS = {
    IP4: IPRange("127.192.0.0", cidr=10)
}

EXT_IPRS = {
    IP4: IPRange("8.192.0.0", cidr=10)
}

ROUTER_IPRS = {
    IP4: IPRange("127.128.0.0", cidr=10)
}

STUN_ADDRS = {
    IP4: {
        "ip": ["127.64.0.1", "127.64.0.2"],
        "port": [3478, 3479]
    }
}


STUN_IP_PRIMARY = 1
STUN_IP_CHANGE = 2
STUN_PORT_PRIMARY = 1
STUN_PORT_CHANGE = 2
STUN_MAPPED_ADDR = b"\x00\x01"
STUN_SRC_ADDR = b"\x00\x04"
STUN_CHANGED_ADDR = b"\x00\x05"

SRC_IP_NO_CHANGE = 0
SRC_PORT_NO_CHANGE = 0

def change_src_mode(af, needle, offset):
    for entry in STUN_ADDRS[af][offset]:
        if entry != needle:
            return entry

def stun_write_attr(attr_type, attr_val):
    buf = attr_type
    buf += (  b"\x00" + i_to_b( len(attr_val) )  )[-2:]
    buf += attr_val
    return buf

def stun_endpoint_attr(end_tup, af):
    ip, port = end_tup[0:2]
    if af == IP6:
        ip = ipv6_norm(ip)
    attr_val = b"\x00\x00" # Some kind of padding.
    attr_val += (  b"\x00" + i_to_b( port )  )[-2:]
    attr_val += socket.inet_aton(ip)
    return attr_val

def lan_ip_to_router_ip(ip):
    lan_ipr = IPRange(ip)
    router_ipr = ROUTER_IPRS[lan_ipr.af]
    router_ipr = router_ipr + (int(lan_ipr) - 1)
    return str(router_ipr)

def lan_ip_to_ext_ip(ip):
    lan_ipr = IPRange(ip)
    ext_ipr = EXT_IPRS[lan_ipr.af]
    ext_ipr = ext_ipr + (int(lan_ipr) - 1)
    return str(ext_ipr)

class STUNRouterServer(Daemon):
    def __init__(self, af, proto, serv_ip, serv_port, routers, serv_pipes):
        super().__init__()
        self.af = af
        self.proto = proto
        self.serv_ip = serv_ip
        self.serv_port = serv_port
        self.routers = routers
        self.serv_pipes = serv_pipes

        self.change_ip = change_src_mode(
            self.af,
            self.serv_ip,
            "ip"
        )

        self.change_port = change_src_mode(
            self.af,
            self.serv_port,
            "port"
        )

        print(f"change port = {self.change_port}")


    async def msg_cb(self, msg, client_tup, pipe):
        try:
            print(f"got stun req from {client_tup} at {self.serv_ip} {self.serv_port}")

            # Source mode for sending responses from.
            src_mode = [
                self.serv_ip,
                self.serv_port
            ]

            print(f"src_mode = {src_mode}")
            print(f"change = {self.change_ip} {self.change_port}")

            # Only accept connections from a certain range.
            af = pipe.route.af
            client_ipr = IPRange(client_tup[0])
            if client_ipr not in CLIENT_IPRS[af]:
                print(f"Client IPR: {client_ipr} error.")
                return


            # Minimum request size.
            msg_len = len(msg)
            if msg_len < 20:
                print("1")
                return

            # Unpack request.
            hdr = msg[0:2]
            extra_len = b_to_i(msg[2:4])
            tran_id = msg[4:20]
            extra = msg[20:]
            if len(extra):
                extra = to_s(binascii.b2a_hex(extra))
                print(f"extra = {extra}")

                # Change source IP.
                if extra == changeRequest:
                    print("CHANGE IP REQUEST")
                    src_mode[0] = self.change_ip
                    src_mode[1] = self.change_port

                # Change source port.
                if extra == changePortRequest:
                    print("CHANGE PORT REQUEST")
                    src_mode[1] = self.change_port
            else:
                extra = None

            # Check hdr.
            if hdr != b"\x00\x01":
                print("2")
                return

            # Get fields to send back based on their 'router.'
            router_ip = lan_ip_to_router_ip(client_tup[0])
            print(f"using router: {router_ip}")
            print(f"using params: {self.af} {self.proto} {src_mode}")

            router = self.routers[router_ip]
            mapping = router.request_approval(
                self.af,
                self.proto,
                src_mode[0],
                src_mode[1],
                client_tup[0],
                client_tup[1],
                router_ip
            )

            # If their router rejected it then return.
            if not mapping:
                print("Router rejected this.")
                return

            print(f"accepted {mapping}")

            # Bind response msg.
            reply = b"\x01\x01"

            # Write external address and port view.
            ext_tup = list(client_tup[:])
            if router.nat["type"] == OPEN_INTERNET:
                ext_tup[0] = client_tup[0]
            else:
                ext_tup[0] = lan_ip_to_ext_ip(client_tup[0])
            ext_tup[1] = mapping
            attrs = stun_write_attr(
                STUN_MAPPED_ADDR,
                stun_endpoint_attr(ext_tup, af)
            )

            # Write the servers own local address.
            attrs += stun_write_attr(
                STUN_SRC_ADDR,
                stun_endpoint_attr(
                    (self.serv_ip, self.serv_port),
                    af
                )
            )

            # Write the servers change address details.
            attrs += stun_write_attr(
                STUN_CHANGED_ADDR,
                stun_endpoint_attr(
                    (
                        self.change_ip,
                        self.change_port
                    ),
                    af
                )
            )

            # Attr len.
            reply += (  b"\x00" + i_to_b( len(attrs) )  )[-2:]

            # Tran id.
            reply += tran_id

            # Attrs.
            reply += attrs

            # Send reply (possible from different endpoint.)
            # TODO: if TCP -- make a new connection.
            out_pipes = self.serv_pipes[af][self.proto]
            out_pipe = out_pipes[src_mode[0]][src_mode[1]]

            print(out_pipe.sock)
            print(reply)
            await out_pipe.send(reply, client_tup)
        except:
            log_exception()

class Router():
    def __init__(self, nat, nat_ip):
        self.nat = nat
        self.nat_ip = nat_ip

        self.approvals = {
            IP4: { UDP: {}, TCP: {} },
            IP6: { UDP: {}, TCP: {} },
        }

        self.mappings = {
            IP4: { UDP: {}, TCP: {} },
            IP6: { UDP: {}, TCP: {} },
        }

        self.deltas = {
            IP4: { UDP: {}, TCP: {} },
            IP6: { UDP: {}, TCP: {} },
        }

    # Used to track increasing delta values for mapping ports.
    def init_delta(self, af, proto, lan_ip):
        deltas = self.deltas[af][proto]
        if lan_ip not in deltas:
            rand_port = from_range(self.nat["range"])
            deltas[lan_ip] = {
                # Random start port.
                "start": rand_port,

                # Tracked current port.
                "value": rand_port,

                # Local delta.
                "local": 0
            }

    def get_mapping_id(self, af, proto, src_ip, src_port, lan_ip, lan_port):
        mapping_id = [lan_ip, lan_port, 0, 0]


        if self.nat["type"] in [RESTRICT_NAT, RESTRICT_PORT_NAT]:
            mapping_id[2] = src_ip

        if self.nat["type"] == RESTRICT_PORT_NAT:
            mapping_id[3] = src_port

        return tuple(mapping_id)

    # Allocates a new port for use with a new mapping.
    # TODO: fix with new logic
    def request_port(self, af, proto, src_ip, src_port, lan_ip, nat_ip):
        delta_type = self.nat["delta"]["type"]
        mappings = self.mappings[af][proto]
        deltas = self.deltas[af][proto][lan_ip]
        port = 0

        # The NAT reuses the same src_port.
        if delta_type == EQUAL_DELTA:
            if lan_ip not in mappings:
                return src_port
            else:
                port = src_port

        # The distance between local ports is applied to
        # a fixed port offset to define remote mappings.
        if delta_type == PRESERV_DELTA:
            port = field_wrap(
                src_port + self.nat["delta"]["value"],
                self.nat["range"]
            )

        """
        There's a random, fixed-value 'delta' (either positive,
        or negative, sometimes even algebraic but this isn't
        covered) and its added to a past port allocation to
        yied a new number. The start port can be random.
        """
        if delta_type == INDEPENDENT_DELTA:
            delta = deltas["value"] + self.nat["delta"]["value"]
            port = field_wrap(
                delta,
                self.nat["range"]
            )

            # Save new allocation port value.
            deltas["value"] = port

        """
        The distance between allocated ports also depends on
        the source port. So if you want to know what remote
        mappings occur you need to preserve the same delta
        in local port mappings.
        """
        if delta_type == DEPENDENT_DELTA:
            delta = deltas["start"] + (self.nat["delta"]["value"] * src_port)
            port = field_wrap(
                delta,
                self.nat["range"]
            )



        # Request port is already allocated.
        # Use the first free port from that offset.
        while 1:
            #mapping_id = self.get_mapping_id(af, proto, src_ip, src_port, lan_ip, port)
            if port in mappings[nat_ip]:
                port = from_range(self.nat["range"])
            else:
                break

        return port

    """
    Used by their connect on own NAT to simulate 'openning' the NAT by us.
    dst... = not where you're connecting to -- their local address
    used to connect to our NAT.
    src... = the local addressing details for the con
    """
    def accept_connect(self, af, proto, src_ip, src_port, lan_ip, lan_port, nat_ip):
        # Reuse an existing mapping if it exists.
        mapping = None
        mappings = self.mappings[af][proto]
        if nat_ip not in mappings:
            self.mappings[af][proto][nat_ip] = {}
        print(f" nat type = {self.nat['type']}")
        
        """
        same mapping:
            full cone:
                - bound to lan ip lan port

            restrict:
                - bound to a specifid src_ip, lan ip, lan port

            restrict:
                - optionally a specific src_port

            symmetric:
                - per con

            
        """


        mapping_id = self.get_mapping_id(af, proto, src_ip, src_port, lan_ip, lan_port)
        if mapping_id in mappings[nat_ip]:
            mapping = mappings[nat_ip][mapping_id]
        print(mapping_id)

        # Otherwise create a new mapping.
        reuse_nats = [FULL_CONE, RESTRICT_NAT, RESTRICT_PORT_NAT]
        if mapping is None:
            # Only certain NATs need a new 'mapping.'
            create_nats = reuse_nats + [SYMMETRIC_NAT]
            if self.nat["type"] in create_nats:
                # Request new port for the mapping.
                print("create nat")
                self.init_delta(af, proto, lan_ip)
                nat_port = self.request_port(
                    af,
                    proto,
                    src_ip,
                    src_port,
                    lan_ip,
                    nat_ip
                )
                print("got = ", nat_port)

                # The mappings are indexed by local endpoints.
                mapping = [af, proto, lan_ip, lan_port, nat_port]
                mappings[nat_ip][mapping_id] = mapping
                mappings[nat_ip][nat_port] = mapping

                # Mappings are also indexed by destination.
                #dst_endpoint = str([dst_ip, dst_port])
                #mappings[nat_ip][dst_endpoint] = mapping

        # Add dst ip and port to approvals.
        self.approvals.setdefault(nat_ip, {})
        self.approvals[nat_ip].setdefault(src_ip, {})
        self.approvals[nat_ip][src_ip][src_port] = 1

        # Return results.
        if mapping is not None:
            return mapping[-1]

        # Return results.
        return 0

    # The other side calls this which returns a mapping
    # based on whether there's an approval + the nat setup.
    def request_approval(self, af, proto, src_ip, src_port, lan_ip, lan_port, nat_ip):
        # Blocked.
        if self.nat["type"] in [BLOCKED_NAT, SYMMETRIC_UDP_FIREWALL]:
            print("a")
            return 0

        # Open internet -- can use any inbound port.
        if self.nat["type"] == OPEN_INTERNET:
            return lan_port

        # No mappings for this NAT IP exist.
        mappings = self.mappings[af][proto]
        if nat_ip not in mappings:
            print("c")
            return 0



        mapping_id = self.get_mapping_id(af, proto, src_ip, src_port, lan_ip, lan_port)
        print(f"req approval = {mapping_id}")
        
        if mapping_id not in mappings[nat_ip]:
            print("b")
            return 0

        approvals = self.approvals[nat_ip]
        if self.nat["type"] in [RESTRICT_NAT, RESTRICT_PORT_NAT]:
            if src_ip not in self.approvals[nat_ip]:
                print("d")
                return 0

        if self.nat["type"] == RESTRICT_PORT_NAT:
            if src_port not in self.approvals[nat_ip][src_ip]:
                print("e")
                return 0

        return lan_port

        mapping = mappings[nat_ip][mapping_id]
        return mapping[-1]


def patch_sock_connect(routers, loop=None):
    routers_ipr = IPRange("127.128.0.0", cidr=10)
    lans_ipr = IPRange("127.64.0.0", cidr=10)
    loop = loop or asyncio.get_event_loop()
    unpacked_connect = loop.sock_connect

    async def patched_connect(sock, dest_tup):
        src_tup = sock.getsockname()
        src_ipr = IPRange(src_tup[0])
        dest_ipr = IPRange(dest_tup[0])

        # Connection to another virtual LAN machine.
        if src_ipr in lan_ipr and dest_ipr in lan_ipr:
            # Convert to our router IP.
            our_router_ip = lan_ip_to_router_ip(src_tup[0])

            # Get reference to our router.
            our_router = routers[our_router_ip]

            # Whitelist this destination in our router.
            our_router.approve_inbound(
                af=src_ipr.af,
                proto=sock.type,
                src_ip=src_tup[0],
                src_port=src_tup[1],
                dst_ip=dest_tup[0],
                dst_port=dst_port[1],
                nat_ip=our_router_ip
            )

            # Convert to their router IP.
            their_router_ip = lan_ip_to_router_ip(dest_tup[0])

            # Get reference to their router.
            their_router = routers[their_router_ip]

            # Check if we're allow to connect to them.
            ret = their_router.request_approval(
                af=src_ipr.af,
                proto=sock.type,



                dst_ip=dest_tup[0],
                dest_port=dest_port[1],
                nat_ip=their_router_ip
            )

            if ret is 0:
                raise Exception("Sim NAT router returned 0.")
            

        return await unpacked_connect(sock, dest_tup)

    return patched_connect

# Patch get mapping?
# get_nat_predictions
"""
                _, s, local_port, remote_port, _, _ = await stun_client.get_mapping(
                    proto=STREAM,
                    source_port=high_port
                )

STUN client get_mapping needs to be patched but what instance of stun_client
    p2p_pipe.py
        stun_client
            get_mapping
"""

def nat_approve_pipe(pipe, dest_tup, routers):
    # Get a reference to the router for this machine.
    local_tup = pipe.sock.getsockname()
    router_ip = lan_ip_to_router_ip(local_tup[0])
    router = routers[router_ip]
    print(f"patched: {local_tup} {dest_tup} {router_ip}")
    print(pipe.route.af)
    print(pipe.sock.type)

    # Create a new mapping.
    mapping = router.accept_connect(
        af=pipe.route.af,
        proto=pipe.sock.type,
        src_ip=dest_tup[0],
        src_port=dest_tup[1],
        lan_ip=local_tup[0],
        lan_port=local_tup[1],
        nat_ip=router_ip
    )

    print(f"mapping p: {mapping} {router.mappings}")

def patch_init_pipe(init_pipe, routers):
    async def patched(dest_addr, interface, af, proto, source_port, local_addr=None, conf=STUN_CONF):
        try:
            pipe = await init_pipe(
                dest_addr,
                interface,
                af,
                proto,
                source_port,
                local_addr,
                conf
            )

            nat_approve_pipe(pipe, routers)


            return pipe
        except:
            log_exception()

    return patched

"""
Patch interface.route to use the local nic ipr.

Then put it all together.

1. manually set interface.unique_loopback
2. create the punch nodes for the test
"""

async def nat_sim_node(loopback, nat, routers):
    # Create router instance.
    router_ip = lan_ip_to_router_ip(loopback)
    router = Router(nat, router_ip)
    routers[router_ip] = router

    # Patch sock connect.
    loop = asyncio.get_event_loop()
    loop.sock_connect = patch_sock_connect(routers)

    # Initialize interface.
    interface = await Interface.start_local()
    interface.unique_loopback = loopback

    # Load clock skew for test machine.
    if not hasattr(nat_sim_node, "clock_skew"):
        nat_sim_node.clock_skew = (await SysClock(interface).start()).clock_skew

    # Load process pool executors.
    pp_executors = await get_pp_executors(workers=2)

    # Start the main node.
    node = await start_p2p_node(
        node_id=node_name(b"nat_sim_node" + rand_plain(8), interface),

        # Get brand new unassigned listen port.
        # Avoid TIME_WAIT buggy sockets from port reuse.
        port=0,
        ifs=[interface],
        clock_skew=nat_sim_node.clock_skew,
        pp_executors=pp_executors,
        enable_upnp=False
    )

    # Patch the mapping function for the STUNClient.
    node.STUNClient.get_mapping = patch_get_mapping(routers)

    return node

async def start_stun_servs(af, proto, interface, routers):
    serv_pipes = {
        IP4: {
            UDP: {}, TCP: {}
        },
        IP6: {
            UDP: {}, TCP: {}
        },
    }
    servs = copy.deepcopy(serv_pipes)


    for serv_ip in STUN_ADDRS[af]["ip"]:
        for serv_port in STUN_ADDRS[af]["port"]:
            # Listen details.
            route = await interface.route(af).bind(
                ips=serv_ip,
                port=serv_port
            )

            serv = STUNRouterServer(
                af=af,
                proto=proto,
                serv_ip=serv_ip,
                serv_port=serv_port,
                routers=routers,
                serv_pipes=serv_pipes
            )

            await serv.listen_specific(
                targets=[[route, proto]],
            )

            # Server 0, offset 2 is the pipe.
            # Need to make this more clean in the future...
            serv_pipe = serv.servers[0][2]
            if serv_ip not in serv_pipes[af][proto]:
                serv_pipes[af][proto][serv_ip] = {}
                servs[af][proto][serv_ip] = {}

            serv_pipes[af][proto][serv_ip][serv_port] = serv_pipe
            servs[af][proto][serv_ip][serv_port] = serv

    return serv_pipes, servs

async def close_stun_servs(servs):
    tasks = []
    for af in [IP4, IP6]:
        for proto in [TCP, UDP]:
            sub_servs = servs[af][proto]
            for serv_ip in sub_servs:
                sub_serv = sub_servs[serv_ip]
                for serv_port in sub_serv:
                    serv = sub_serv[serv_port]
                    tasks.append(serv.close())

    await asyncio.gather(*tasks)

def patch_route(af, ip, interface):
    def patched(af_ignore=None, bind_port=0):
        return Route(
            af=af,
            nic_ips=[IPRange(ip)],
            ext_ips=[IPRange(ip)],
            interface=interface,
            ext_check=0
        )

    return patched

async def nat_sim_main():
    # Single simulated router.
    delta = delta_info(DEPENDENT_DELTA, 10)
    nat = nat_info(SYMMETRIC_NAT, delta)
    nat_ip = IPRange("127.128.0.1", cidr=32)
    router = Router(nat, nat_ip)
    routers = {
        str(nat_ip): router
    }


    af = IP4
    proto = UDP
    interface = await Interface().start_local()
    stun_serv_pipes, stun_servs = await start_stun_servs(
        af,
        proto,
        interface,
        routers
    )


    print(stun_serv_pipes)

    print("stun servs started")


    interface.route = patch_route(af, "127.192.0.1", interface)
    stun_client = STUNClient(
        interface=interface,
        af=af,
        proto=proto
    )

    init_pipe_original = stun_client.init_pipe
    stun_client.init_pipe = patch_init_pipe(
        init_pipe_original,
        routers
    )

    stun_servers = [
        {
            "host": "local_hax",
            "primary": {"ip": "127.64.0.1", "port": 3478},
            "secondary": {"ip": "127.64.0.2", "port": 3479},
        },
    ]

    STUND_SERVERS[IP4] = stun_servers

    """
    print("before get mappings")
    ret = await stun_client.get_mapping(proto, servers=stun_servers)
    print(ret)

    symmetric independent delta
    """

    route = await interface.route(af).bind()
    pipe = await pipe_open(UDP, route=route, conf=STUN_CONF)
    print("load nat pipe.")
    print(pipe.sock)
    pipe.routers = routers
    pipe.nat_approve_pipe = nat_approve_pipe

    #nat_approve_pipe(pipe, routers)
    # nat_test_exec needs to be patched to approve the dest

    """
    serv_info = [stun_servers[0]["primary"]["ip"], 3478]
    nat_approve_pipe(pipe, serv_info, routers)
    serv_info = [stun_servers[0]["secondary"]["ip"], 3478]
    nat_approve_pipe(pipe, serv_info, routers)
    """

    ret = await interface.load_nat(stun_client, stun_servers, pipe)
    print(ret)
    


    await close_stun_servs(stun_servs)

    return





    interface = await Interface().start_local()
    interface.unique_loopback = "127.64.0.1"
    stun_client = STUNClient(interface)
    stun_client.get_mapping = patch_get_mapping(routers, stun_client)

    out = await stun_client.get_mapping(UDP, source_port=50000)
    print(out)

    out = await stun_client.get_mapping(UDP, source_port=50001)
    print(out)

    print(router.deltas)
    print()
    print(router.mappings)
    print()
    print(router.approvals)


    ret = await interface.load_nat(stun_client, stun_servers, pipe)
    print(ret)

    return



    af = IP4
    proto = TCP
    int_ipr = IPRange("127.64.0.0", cidr=10)
    src_port = 1337

    ext_ipr = IPRange("127.128.0.0", cidr=10)

    print(int_ipr)
    print(len(int_ipr))


    n1 = nat_info(RESTRICT_NAT, delta=delta_info(DEPENDENT_DELTA, 10))
    r1 = Router(n1)
    r1.init_delta(af, proto, str(ext_ipr + 0))


 
    p1 = r1.request_port(af, proto, str(int_ipr + 0), src_port, str(ext_ipr + 0))
    print(p1)
    p1 = r1.request_port(af, proto, str(int_ipr + 0), src_port + 3, str(ext_ipr + 0))
    print(p1)

    m1 = r1.approve_inbound(
        af,
        proto,
        str(int_ipr + 0),
        1337,
        str(ext_ipr + 0),
        10123,
        str(ext_ipr + 1)
    )

    print(m1)

    a1 = r1.request_approval(
        af,
        proto,
        str(ext_ipr + 0),
        m1,
        str(ext_ipr + 1)
    )

    print(a1)




    return
    route = await i.route().bind(port=test_port, ips=ip)
    stun_server = STUNServer(STUN_IP_PRIMARY, STUN_PORT_PRIMARY)
    await stun_server.listen_specific(
        [[route, proto]]
    )
    print(stun_server)
    
    stun_client = STUNClient(i)

    servers = [
        {
            "host": "local",
            # i.route().nic()
            "primary": {"ip": ip, "port": test_port},
            "secondary": {"ip": ip, "port": test_port},
        },
    ]


    ret = await stun_client.get_mapping(
        proto=proto,
        servers=servers
    )

    await stun_server.close()

    print(ret)
    print(ret[1].sock)

async_test(nat_sim_main)


"""



"""