import asyncio
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
from decimal import Decimal as Dec
from .p2p_pipe import *
from .daemon import *
from .signaling import *

NODE_CONF = dict_child({
    # Reusing address can hide errors for the socket state.
    # This can make servers appear to be broken when they're not.
    "reuse_addr": False,
}, NET_CONF)

class P2PNode(Daemon):
    def __init__(self, if_list, port=NODE_PORT, node_id=None, ip=None, signal_offsets=None, enable_upnp=False, conf=NODE_CONF):
        super().__init__()
        self.conf = conf
        self.signal_offsets = signal_offsets
        self.port = port
        self.enable_upnp = enable_upnp
        self.ip = ip
        self.if_list = if_list
        self.ifs = Interfaces(if_list)
        self.node_id = node_id or rand_plain(15)
        self.signal_pipes = {} # offset into MQTT_SERVERS
        self.expected_addrs = {} # by [pipe_id]
        self.pipe_events = {} # by [pipe_id]
        self.pipes = {} # by [pipe_id]
        self.sys_clock = None
        self.pp_executor = None
        self.mp_manager = None
        self.tcp_punch_clients = None # [...]
        self.turn_clients = []

        # Handlers for the node's custom protocol functions.
        self.msg_cbs = []

        # Maps p2p's ext to pipe_id.
        self.pending_pipes = {} # by [pipe_id]
        self.is_running = True
        self.listen_all_task = None
        self.signal_worker_task = None
        self.signal_worker_tasks = {} # offset into MQTT_SERVERS

    # Given a dict of credentials find the associated client.
    def find_turn_client(self, turn_server, af=None, interface=None):
        for turn_client in self.turn_clients:
            # Get credentials for turn client.
            credentials = turn_client.get_turn_server(af=af)

            # Compare credentials to turn_server.
            is_same = find_turn_server(credentials, [turn_server])
            if not is_same:
                continue

            # Not the same interface.
            if interface is not None:
                if turn_client.turn_pipe.route.interface != interface:
                    continue

            # Otherwise found it.
            return turn_client

        return None

    def find_signal_pipe(self, addr):
        our_offsets = list(self.signal_pipes)
        for offset in addr["signal"]:
            if offset in our_offsets:
                return self.signal_pipes[offset]

        return None

    async def forward(self, port):
        tasks = []
        for server in self.servers:
            # Get the bind IP and interface for the route.
            route = server[0]

            # Only forward to public IPv6 addresses.
            ipr = IPRange(route.bind_ip(route.af))
            if route.af == IP6 and ipr.is_private:
                continue

            # Make task to forward this route.
            task = route.forward(port)
            tasks.append(task)

        # Get a list of tasks to do forwarding or pin holes.
        results = await asyncio.gather(*tasks)
        tasks = []
        for result in results:
            if len(result):
                tasks += result

        # Now do that all at once since it might take a while.
        if len(tasks):
            await asyncio.gather(*tasks)

    async def start(self, protos=[TCP]):
        # MQTT server offsets to try.
        if self.signal_offsets is None:
            offsets = [0] + shuffle([i for i in range(1, len(MQTT_SERVERS))])
        else:
            offsets = self.signal_offsets

        # Get list of N signal pipes.
        for _ in range(0, SIGNAL_PIPE_NO):
            async def set_signal_pipe(offset):
                mqtt_server = MQTT_SERVERS[offset]
                signal_pipe = SignalMock(
                    peer_id=to_s(self.node_id),
                    f_proto=self.signal_protocol,
                    mqtt_server=mqtt_server
                )

                try:
                    await signal_pipe.start()
                    self.signal_pipes[offset] = signal_pipe
                    return signal_pipe
                except Exception:
                    if signal_pipe.is_connected:
                        await signal_pipe.close()
                    return None
            
            # Traverse list of shuffled server indexes.
            while 1:
                # If tried all then we're done.
                if not len(offsets):
                    break

                # Get the next offset to try.
                offset = offsets.pop(0)

                # Try to use the server at the offset for a signal pipe.
                signal_pipe = await async_wrap_errors(
                    set_signal_pipe(offset)
                )

                # The connection failed so keep trying.
                if signal_pipe is None:
                    continue
                else:
                    break

        # Check at least one signal pipe was set.
        if not len(self.signal_pipes):
            raise Exception("Unable to get any signal pipes.")

        # Make a list of routes based on supported address families.
        routes = []
        if_names = []
        for interface in self.if_list:
            for af in interface.supported():
                route = await interface.route(af).bind()
                routes.append(route)

            if_names.append(interface.name)

        # Do deterministic bind to port by NIC IPs.
        if self.port == -1:
            self.port = get_port_by_ips(if_names)
            for _ in range(0, 2):
                try:
                    self.listen_all_task = await self.listen_all(
                        routes,
                        [self.port],
                        protos
                    )
                    break
                except Exception:
                    # Use any port.
                    log(f"Deterministic bind for node server failed.")
                    log(f"Port {self.port} was not available.")
                    self.port = 0
        else:
            # Start handling messages for self.msg_cb.
            # Bind to all ifs provided to class on route[0].
            self.listen_all_task = await self.listen_all(
                routes,
                [self.port],
                protos
            )

        # Translate any port 0 to actual assigned port.
        # First server, field 3 == base_proto.
        # sock = listen sock, getsocketname = (bind_ip, bind_port, ...)
        port = self.servers[0][2].sock.getsockname()[1]
        self.addr_bytes = make_peer_addr(self.node_id, self.if_list, list(self.signal_pipes), port=port, ip=self.ip)
        self.p2p_addr = parse_peer_addr(self.addr_bytes)
        log(f"> P2P node = {self.addr_bytes}")

        # Do port forwarding if enabled.
        # Maybe this should go in the route class?
        if self.enable_upnp:
            # UPnP has no unit tests so wrap all errors for now.
            await async_wrap_errors(
                self.forward(port)
            )
            
        return self

    def add_msg_cb(self, msg_cb):
        self.msg_cbs.append(msg_cb)

    def del_msg_cb(self, msg_cb):
        if msg_cb in self.msg_cbs:
            self.msg_cbs.remove(msg_cb)

    def rm_pipe_id(self, pipe_id):
        def closure(data, client_tup, pipe):
            # Delete reference to pipe.
            log(f"Running rm pipe id {pipe_id}")
            if pipe_id in self.pipes:
                del self.pipes[pipe_id]

        return closure

    def setup_multiproc(self, pp_executor, mp_manager):
        # Process pools are disabled.
        if pp_executor is None:
            self.pp_executor = None
            self.mp_manager = None
            return
            
        assert(mp_manager)
        self.pp_executor = pp_executor
        self.mp_manager = mp_manager

    def setup_coordination(self, sys_clock):
        self.sys_clock = sys_clock

    def setup_tcp_punching(self):
        self.tcp_punch_clients = [
            TCPPunch(
                interface,
                self.if_list,
                self.sys_clock,
                self.pp_executor,
                self.mp_manager
            )
            for interface in self.if_list
        ]

    def _parse_mappings(self, parts):
        if len(parts) != 9:
            raise Exception("Invalid length for mappings msg.")

        # Extract fields from message.
        r = parse_punch_response(parts)
        p2p_dest = work_behind_same_router(self.p2p_addr, r["src_addr"])

        # Check the address family is valid.
        if r["af"] not in VALID_AFS:
            raise Exception("Invalid af for mappings msg.")

        # Check their chosen interface offset for ourselves is valid.
        if r["if"]["us"] > (len(self.if_list) - 1):
            raise Exception("Invalid if us offset for mappings.")

        # Check their used interface offset is valid.
        their_if_infos = r["src_addr"][r["af"]]
        if r["if"]["them"] > (len(their_if_infos) - 1):
            raise Exception("Invalid if them offset for mappings.")

        # Return main fields.
        their_if_info = their_if_infos[r["if"]["them"]]
        return r, p2p_dest, their_if_infos, their_if_info

    async def signal_protocol(self, msg, signal_pipe):
        # Convert to string because this is a plain-text protocol.
        if isinstance(msg, memoryview):
            msg = to_s(msg.tobytes())
        else:
            msg = to_s(msg)

        # Split msg into parts.
        log(f"> signal proto msg = {msg}")
        parts = msg.split(" ")
        cmd = parts[0]

        # Basic echo protocol for testing.
        if cmd == "ECHO":
            if len(parts) >= 2:
                if isinstance(parts[1], memoryview):
                    chan_dest = parts[1].tobytes()
                else:
                    chan_dest = parts[1]


                # cmd sp node_id sp msg
                offset = (6 + len(chan_dest))
                out = msg[offset:]
                if len(out):
                    if isinstance(out, memoryview):
                        out = out.tobytes()

                    await signal_pipe.send_msg(out, chan_dest)

            return

        # Reverse connect signal.
        if cmd == "P2P_DIRECT":
            if len(parts) != 4:
                log("> invalid p2p direct msg recv.")
                return 1

            # Process message fields.
            pipe_id, proto, addr_bytes = parts[1], parts[2], parts[3]
            proto = PROTO_LOOKUP[proto]
            pipe_id = to_b(pipe_id)
            addr_bytes = to_b(addr_bytes)
            p2p_dest = parse_peer_addr(addr_bytes)
            p2p_dest = work_behind_same_router(self.p2p_addr, p2p_dest)
            log(f"p2p direct proto no = {proto}")

            # Connect to chosen address.
            p2p_pipe = P2PPipe(self)
            try:
                pipe = await asyncio.wait_for(
                    p2p_pipe.direct_connect(p2p_dest, pipe_id, proto=proto),
                    10
                )
            except asyncio.TimeoutError:
                log("p2p direct timeout in node.")
                return

            # Setup pipe reference.
            if pipe is not None:
                log("p2p direct in node got a valid pipe.")

                # Record pipe reference.
                self.pipes[pipe_id] = pipe

                # Add cleanup callback.
                pipe.add_end_cb(self.rm_pipe_id(pipe_id))

            return

        # Request to start TCP hole punching.
        if cmd == "INITIAL_MAPPINGS":
            # Parse mappings to dict.
            ret = self._parse_mappings(parts)
            r, p2p_dest, their_if_infos, their_if_info = ret

            # Create hole punching client.
            interface = self.if_list[r["if"]["us"]]
            stun_client = STUNClient(interface=interface, af=r["af"])
            recipient = self.tcp_punch_clients[r["if"]["us"]]

            # Calculate punch mode.
            their_addr = await Address(str(their_if_info["ext"]), 80).res(interface.route(r["af"]))
            punch_mode = recipient.get_punch_mode(their_addr)
            if punch_mode == TCP_PUNCH_REMOTE:
                use_addr = str(their_if_info["ext"])
            else:
                use_addr = str(their_if_info["nic"])
            
            # Step 2 -- exchange initiator mappings with recipient.
            punch_ret = await recipient.proto_recv_initial_mappings(
                use_addr,
                their_if_info["nat"],
                r["src_addr"]["node_id"],
                r["pipe_id"],
                r["predictions"],
                stun_client,
                r["ntp_time"],
                mode=punch_mode
            )

            # Build second (optional) punch message for peer.
            out = build_punch_response(
                b"UPDATED_MAPPINGS",
                r["pipe_id"],
                punch_ret,
                self.addr_bytes,
                r["af"],
                r["if"]["us"], # Which iface we're using from our addr.
                r["if"]["them"] # Which iface they should use.
            )

            # Send first protocol signal message to peer.
            send_task = asyncio.create_task(
                async_wrap_errors(
                    signal_pipe.send_msg(
                        out,
                        to_s(r["src_addr"]["node_id"])
                    )
                )
            )

            # Do the hole punching.
            try:
                pipe = await asyncio.wait_for(
                    get_tcp_hole(
                        PUNCH_RECIPIENT,
                        r["pipe_id"],
                        r["src_addr"]["node_id"],
                        recipient,
                        self
                    ),
                    30
                )
            except asyncio.TimeoutError:
                log("node tcp punch timeout.")
                return

            return

        # Additional info for doing TCP hole punching.
        if cmd == "UPDATED_MAPPINGS":
            # Unpack mapping fields and parse.
            ret = self._parse_mappings(parts)
            r, p2p_dest, their_if_infos, their_if_info = ret

            # Make a STUN client that can get mappings.
            # This actually shouldn't be needed.
            dest_s = str(their_if_info["ext"])
            af = af_from_ip_s(dest_s)
            interface = self.if_list[r["if"]["us"]]
            stun_client = STUNClient(interface, af)

            # Update received mappings.
            # This is an optional step that can improve connect success.
            initiator = self.tcp_punch_clients[r["if"]["us"]]
            ret = await initiator.proto_update_recipient_mappings(
                r["src_addr"]["node_id"],
                r["pipe_id"],
                r["predictions"],
                stun_client
            )

            return

        """
        Requests that a peer use a specified TURN server to connect
        back to a source peer. The peer provides it's 'mapped address'
        -- the external address of the peer seen from the TURN server's
        perspective. They are expected to 'white list' this address.
        A 'relay address' is also specified for sending messages back
        to the source. Towards the end this node will exchange its own
        mapped and relay address back to the source.
        """
        if cmd == "TURN_REQUEST":
            if len(parts) != 12:
                log("> turn_req: invalid parts len")
                return
            
            # Extract all fields from the signal msg.
            pipe_id = to_b(parts[1])
            af = int(parts[2])
            their_if_index = int(parts[3])
            our_if_index = int(parts[4])
            src_addr_bytes = to_b(parts[5])
            peer_ip = parts[6]
            peer_port = int(parts[7])
            relay_ip = parts[8]
            relay_port = int(parts[9])
            turn_server_index = int(parts[10])
            turn_client_index = int(parts[11])

            # Check turn server index.
            if not in_range(turn_server_index, [0, len(TURN_SERVERS) - 1]):
                log(f"> turn req: servers offset {turn_server_index}")
                return
            else:
                turn_server = TURN_SERVERS[turn_server_index]

            # Check address family is valid.
            if af not in VALID_AFS or af not in turn_server["afs"]:
                log("> turn_req: invalid af")
                return
            
            # Check interface index is valid.
            if not in_range(our_if_index, [0, len(self.if_list) - 1]):
                log("> turn_req: invalid if_index")
                return

            # Check ports are valid.
            for port in [relay_port]:
                if not in_range(port, [1, MAX_PORT]):
                    log("> turn_req: invalid port")
                    return

            # See if TURN server is already connected.
            interface = self.if_list[our_if_index]
            turn_client = self.find_turn_client(turn_server, interface=interface)
            if turn_client is None:
                # Resolve the TURN address.
                route = await interface.route(af).bind()
                turn_addr = await Address(
                    turn_server["host"],
                    turn_server["port"]
                ).res(route)

                # Make a TURN client instance to whitelist them.
                turn_client = TURNClient(
                    route=route,
                    turn_addr=turn_addr,
                    turn_user=turn_server["user"],
                    turn_pw=turn_server["pass"],
                    turn_realm=turn_server["realm"],
                    msg_cb=self.msg_cb
                )

                # Start the TURN client.
                try:
                    await asyncio.wait_for(
                        turn_client.start(),
                        10
                    )
                except asyncio.TimeoutError:
                    log("Turn client start timeout in node.")
                    return

                # Set new TURN client.
                self.turn_clients.append(turn_client)

            # Resolve the peer address.
            # The address here is their XorMappedAddress.
            # The external address of the peer from the TURN server's perspective.
            route = interface.route(af)
            peer_addr = await Address(
                str(peer_ip),
                peer_port
            ).res(route)

            # Resolve relay address.
            relay_addr = await Address(
                relay_ip,
                relay_port
            ).res(route)

            # White list peer.
            try:
                await asyncio.wait_for(
                    turn_client.accept_peer(peer_addr.tup, relay_addr.tup),
                    6
                )
            except asyncio.TimeoutError:
                log("node turn accept peer timeout.")
                return

            # Record the pipe internally.
            client_tup = await turn_client.client_tup_future
            our_relay_tup = await turn_client.relay_tup_future
            self.pipes[pipe_id] = turn_client
            log("> turn_req: our relay tup = {}:{}".format(
                *our_relay_tup
            ))

            # Form response with our addressing info.
            out = b"TURN_RESPONSE %s %s %d %d %s %d %s %d %d" % (
                pipe_id,
                self.node_id,
                af,
                their_if_index,

                # Our own relay addr to route messages to us.
                to_b(our_relay_tup[0]),
                our_relay_tup[1],

                # Our XorMappedAddress.
                to_b(client_tup[0]),
                client_tup[1],

                # Their client to use.
                turn_client_index
            )
            
            # Send response to recipient.
            p2p_src_addr = parse_peer_addr(src_addr_bytes)
            await signal_pipe.send_msg(
                out,
                to_s(p2p_src_addr["node_id"])
            )

        """
        The peer that you requested to contact you back via TURN
        has sent you back this response. The response includes their
        mapped address and their relay address. With this info
        both peers can now start sending messages via each others
        relay addresses and the correct permissions are in place to
        let the packets through. The peers will receive replies from
        the TURN server on the TURN server's regular port. The replies
        will be Send indications with a data attribute and a
        XorPeerAddress attribute that specifies the peer address tuple
        of the packet sender -- which we discard if it doesn't match.
        """
        if cmd == "TURN_RESPONSE":
            # Invalid packet.
            if len(parts) != 10:
                log("> turn_res: invalid parts len")
                return

            # Name all the parts and type convert.
            pipe_id = to_b(parts[1])
            node_id = to_b(parts[2])
            af = int(parts[3])
            if_index = int(parts[4])
            relay_ip = parts[5]
            relay_port = int(parts[6])
            client_ip = IPRange(parts[7])
            client_port = int(parts[8])
            turn_client_index = int(parts[9])

            # Check pipe_id exists.
            if pipe_id not in self.pipe_events:
                log("> turn_res: pipe id not in events")
                return
            if pipe_id not in self.expected_addrs:
                log("> turn_res: pipe id not in turn pending")
                return

            # Check the IP matches what we expect.
            found_exts = self.expected_addrs[pipe_id]
            if client_ip not in found_exts:
                log("> turn_res: client_ip != found ext")
                return

            # Validate ports.
            for port in [relay_port, client_port]:
                if not in_range(port, [1, MAX_PORT]):
                    log("> turn_res: invalid port")
                    return

            # Validate address family.
            if af not in VALID_AFS:
                log("> turn_res: invalid af")
                return

            # Invalid if index.
            if not in_range(if_index, [0, len(self.if_list) - 1]):
                log("> turn_res: if index invalid.")
                return

            # Get turn client.
            if not in_range(turn_client_index, [0, len(self.turn_clients) - 1]):
                log("> turn_resp: invalid turn clietn index.")
                return

            # Get turn client reference.
            turn_client = self.turn_clients[turn_client_index]
            if turn_client is None:
                log("> turn_res: turn client none")
                return

            # Notify waiters that we received the relay address.
            client_tup = (str(client_ip), client_port)
            relay_tup = (relay_ip, relay_port)
            await turn_client.accept_peer(client_tup, relay_tup)
            turn_client.node_events[to_s(node_id)].set()
            return

    async def close(self):
        # Stop node server.
        await super().close()
        self.is_running = False

        # Close the MQTT client.
        for offset in list(self.signal_pipes):
            signal_pipe = self.signal_pipes[offset]
            await signal_pipe.close()

        # Close TCP punch clients.
        for punch_client in self.tcp_punch_clients:
            # Sets close event.
            # Waits for stop event.
            await punch_client.close()

        # Close TURN clients.
        for turn_client in self.turn_clients:
            # Sets state transition to error state to end msg check loop.
            # Closes the open TURN client handle.
            if turn_client is not None:
                await turn_client.close()

        # Cancel all pending p2p_pipes from this node.
        for pipe_task in self.pending_pipes.values():
            pipe_task.cancel()

        """
        Close all open pipes. These may be a mixture of
        inbound cons, outbound cons, servers, or various
        clients. Anything already closed will return.
        """
        for pipe in self.pipes.values():
            await pipe.close()

        # Try close the multiprocess manager.
        try:
            if self.mp_manager is not None:
                self.mp_manager.shutdown()
        except Exception:
            pass

        # Try close the process pool executor.
        try:
            if self.pp_executor is not None:
                self.pp_executor.shutdown()
        except Exception:
            pass

    async def msg_cb(self, msg, client_tup, pipe):
        log(f"> node proto = {msg}, {client_tup}")

        # Execute any custom msg handlers on the msg.
        run_handlers(pipe, self.msg_cbs, client_tup, msg)

        # Execute basic services of the node protocol.
        parts = msg.split(b" ")
        cmd = parts[0]

        # Basic echo server used for testing networking.
        if cmd == b"ECHO":
            if len(msg) > 5:
                await pipe.send(memoryview(msg)[5:], client_tup)

            return

        # This connection was in regards to a request.
        if cmd == b"ID":
            # Invalid format.
            if len(parts) != 2:
                log("ID: Invalid parts len.")
                return 1

            # If no ones expecting this connection its a reverse connect.
            pipe_id = parts[1]
            pipe.add_end_cb(self.rm_pipe_id(pipe_id))
            if pipe_id not in self.pipe_events:
                assert(isinstance(pipe_id, bytes))
                log(f"pipe = '{pipe_id}' not in pipe events. saving.")
                self.pipes[pipe_id] = pipe
            else:
                # Is this IP expected?
                if pipe_id not in self.expected_addrs:
                    log("ID: pipe_id not in expected_addrs.")
                    return 2

                # Check remote address is right.
                exts = self.expected_addrs[pipe_id]
                ipr = IPRange(client_tup[0])
                if ipr not in exts:
                    log("ID: ipr not in expected addrs.")
                    return 3

                # Pipe already saved.
                pipe_event = self.pipe_events[pipe_id]
                if pipe_event.is_set():
                    log("ID: pipe event not set.")
                    return 4

                # Save pipe and notify any waiters about it.
                self.pipes[pipe_id] = pipe
                pipe_event.set()

    async def connect(self, addr_bytes, strategies=P2P_STRATEGIES, timeout=60):
        p2p_pipe = P2PPipe(self)
        return await p2p_pipe.pipe(
            addr_bytes,
            strategies=strategies,
            timeout=timeout
        )

    def address(self):
        return self.addr_bytes

def init_process_pool():
    # Make selector default event loop.
    # On Windows this changes it from proactor to selector.
    asyncio.set_event_loop_policy(SelectorEventPolicy())

    # Create new event loop in the process.
    loop = asyncio.get_event_loop()

async def get_pp_executors(workers=2):
    try:
        pp_executor = ProcessPoolExecutor(max_workers=workers)
    except Exception:
        """
        Not all platform have a working implementation of sem_open / semaphores.
        Android is one such platform. It does support multiprocessing but
        this semaphore feature is missing and will throw an error here.
        In this case -- log the error and revert to using a single event loop.
        """
        log_exception()
        return None
    
    loop = asyncio.get_event_loop()
    tasks = []
    for i in range(0, workers):
        tasks.append(loop.run_in_executor(
            pp_executor, init_process_pool
        ))
    await asyncio.gather(*tasks)
    return pp_executor

# delay with sys clock and get_pp_executors.
async def start_p2p_node(port=NODE_PORT, node_id=None, ifs=None, clock_skew=Dec(0), ip=None, pp_executors=None, enable_upnp=False, signal_offsets=None, netifaces=None):
    # Load NAT info for interface.
    ifs = ifs or await load_interfaces(netifaces=netifaces)
    assert(len(ifs))
    for interface in ifs:
        # Don't set NAT details if already set.
        if interface.resolved:
            continue

        # Prefer IP4 if available.
        af = IP4
        if af not in interface.supported():
            af = IP6

        # STUN is used to test the NAT.
        stun_client = STUNClient(
            interface,
            af
        )

        # Load NAT type and delta info.
        # On a server should be open.
        nat = await stun_client.get_nat_info()
        interface.set_nat(nat)

    if pp_executors is None:
        pp_executors = await get_pp_executors(workers=4)

    if clock_skew == Dec(0):
        sys_clock = await SysClock(ifs[0]).start()
    else:
        sys_clock = SysClock(ifs[0], clock_skew)

    # Log sys clock details.
    assert(sys_clock.clock_skew) # Must be set for meetings!
    log(f"> Start node. Clock skew = {sys_clock.clock_skew}")

    # Pass interface list to node.
    node = await P2PNode(
        if_list=ifs,
        port=port,
        node_id=node_id,
        ip=ip,
        signal_offsets=signal_offsets,
        enable_upnp=enable_upnp
    ).start()

    # Configure node for TCP punching.
    if pp_executors is not None:
        mp_manager = multiprocessing.Manager()
    else:
        mp_manager = None

    node.setup_multiproc(pp_executors, mp_manager)
    node.setup_coordination(sys_clock)
    node.setup_tcp_punching()

    # Wait for MQTT sub.
    for offset in list(node.signal_pipes):
        await node.signal_pipes[offset].sub_ready.wait()

    return node

if __name__ == "__main__": # pragma: no cover
    from .p2p_pipe import P2PPipe, P2P_DIRECT, P2P_REVERSE, P2P_PUNCH, P2P_RELAY
    from .nat import *
    async def test_p2p_node():
        sys_clock = SysClock(Dec("-0.02839018452552057081653225806"))
        pp_executor = ProcessPoolExecutor()
        mp_manager = multiprocessing.Manager()
        #internode_out = await Interface("enp3s0").start()
        starlink_out = await Interface("wlp2s0").start()
        internode_nat = nat_info(PRESERV_NAT, delta_info(PRESERV_NAT, 0))
        starlink_nat = nat_info(RESTRICT_PORT_NAT, delta_info(RANDOM_DELTA, 0), [34000, MAX_PORT])
        #internode_out.set_nat(internode_nat)
        starlink_out.set_nat(starlink_nat)





        alice_node = await P2PNode([starlink_out], 11111).start()
        alice_node.setup_multiproc(pp_executor, mp_manager)
        alice_node.setup_coordination(sys_clock)
        alice_node.setup_tcp_punching()

        
        bob_node = await P2PNode([starlink_out], 22222).start()
        bob_node.setup_multiproc(pp_executor, mp_manager)
        bob_node.setup_coordination(sys_clock)
        bob_node.setup_tcp_punching()
        alice_p2p_pipe = P2PPipe(alice_node)
        

        #print(alice_node.tcp_punch_clients[0].interface.route(IP4))



        """
        print("Testing direct connect.")
        direct_pipe = await alice_p2p_pipe.pipe(
            bob_node.addr_bytes,
            [P2P_DIRECT]
        )
        print(direct_pipe)
        """

        """
        print("Testing reverse connect.")
        reverse_pipe = await alice_p2p_pipe.pipe(
            bob_node.addr_bytes,
            [P2P_REVERSE]
        )
        print(reverse_pipe)
        """

        """
        print("Testing p2p punch.")
        punch_pipe = await alice_p2p_pipe.pipe(
            bob_node.addr_bytes,
            [P2P_PUNCH]
        )
        """

        print("Testing p2p relay.")
        relay_pipe = await alice_p2p_pipe.pipe(
            bob_node.addr_bytes,
            [P2P_RELAY]
        )

        print("Got this pipe from relay = ")
        print(relay_pipe)
        
        await relay_pipe.send(b"Test msg back to bob via turn chan.")   
        print("sent")
        while 1:
            await asyncio.sleep(1)

    async_test(test_p2p_node)

