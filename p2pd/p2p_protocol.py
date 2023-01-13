import asyncio
from .p2p_pipe import *

def parse_mappings(self, parts):
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
        ret = parse_mappings(self, parts)
        r, p2p_dest, their_if_infos, their_if_info = ret

        # Create hole punching client.
        interface = self.if_list[r["if"]["us"]]
        stun_client = STUNClient(interface=interface, af=r["af"])
        recipient = self.tcp_punch_clients[r["if"]["us"]]

        # Calculate punch mode.
        their_addr = await Address(
            str(their_if_info["ext"]),
            80,
            interface.route(r["af"])
            ).res()
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
        ret = parse_mappings(self, parts)
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
                turn_server["port"],
                route
            ).res()

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
            peer_port,
            route
        ).res()

        # Resolve relay address.
        relay_addr = await Address(
            relay_ip,
            relay_port,
            route
        ).res()

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

async def node_protocol(self, msg, client_tup, pipe):
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