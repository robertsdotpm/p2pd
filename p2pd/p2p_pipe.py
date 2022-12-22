import asyncio
import copy
import urllib.parse
from .p2p_addr import *
from .tcp_punch import *
from .turn_client import *

"""
TCP 
nc -4 -l 127.0.0.1 10001 -k
nc -6 -l ::1 10001 -k
"""

P2P_DIRECT = 1
P2P_REVERSE = 2
P2P_PUNCH = 3
P2P_RELAY = 4

# TURN is not included as a default strategy because it uses UDP.
# It will need a special explanation for the developer.
# SOCKS might be a better protocol for relaying in the future.
P2P_STRATEGIES = [P2P_DIRECT, P2P_REVERSE, P2P_PUNCH]

async def get_tcp_hole(side, pipe_id, node_id, punch_client, node):
    pipe = None
    try:
        pipe = await punch_client.proto_do_punching(
            side,
            node_id,
            pipe_id,
            node.msg_cb
        )
    except:
        log_exception()

    if pipe is not None:
        # Save pipe reference.
        node.pipes[pipe_id] = pipe

        # Notify any waiters.
        if pipe_id in node.pipe_events:
            node.pipe_events[pipe_id].set()

        # Add cleanup callback.
        pipe.add_end_cb(node.rm_pipe_id(pipe_id))

    return pipe

"""
If nodes are behind the same router they will have
the same external address. Using this address for
connections will fail because it will be the same
address as ourself. The solution here is to replace
that external address with a private, NIC address.
For this reason the P2P address format includes
a private address section that corrosponds to
the address passed to bind() for the nodes listen().
"""
def work_behind_same_router(src_addr, dest_addr):
    new_addr = copy.deepcopy(dest_addr)
    for af in VALID_AFS:
        for dest_info in new_addr[af]:
            for src_info in src_addr[af]:
                # Same external address as one of our own.
                if dest_info["ext"] == src_info["ext"]:
                    # Connect to its internal address instead.
                    dest_info["ext"] = dest_info["nic"]

                    # Disable NAT in LANs.
                    delta = delta_info(NA_DELTA, 0)
                    nat = nat_info(OPEN_INTERNET, delta)
                    dest_info["nat"] = nat

    return new_addr

def build_reverse_msg(pipe_id, addr_bytes, b_proto=b"TCP"):
    out = b"P2P_DIRECT %s %s %s" % (pipe_id, b_proto, addr_bytes) 
    return out

def build_punch_response(cmd, pipe_id, punch_ret, src_addr_bytes, af, our_if_index, their_if_index):
    def mappings_to_bytes(mappings):
        pairs = []
        for pair in mappings:
            # remote, reply, local.
            pairs.append( b"%d,%d,%d" % (pair[0], pair[1], pair[2]) )

        return b"|".join(pairs)

    #      cm pip se nt pr ad af (if indexs)
    out = b"%s %s %d %s %s %s %d %d %d" % (
        cmd,
        pipe_id,
        0, # session id.
        to_b(str(punch_ret[1])), # ntp
        mappings_to_bytes(punch_ret[0]), # predictions
        src_addr_bytes,
        af,
        our_if_index,
        their_if_index
    )

    return out

def parse_prediction_str(s_predictions):
    predictions = []
    prediction_strs = s_predictions.split("|")
    for prediction_str in prediction_strs:
        remote_s, reply_s, local_s = prediction_str.split(",")
        prediction = [to_n(remote_s), to_n(reply_s), to_n(local_s)]
        if not in_range(prediction[0], [1, MAX_PORT]):
            raise Exception(f"Invalid remote port {prediction[0]}")

        if not in_range(prediction[-1], [1, MAX_PORT]):
            raise Exception(f"Invalid remote port {prediction[-1]}")

        predictions.append(prediction)

    if not len(predictions):
        raise Exception("No predictions received.")

    return predictions

def parse_punch_response(parts):
    return {
        "cmd": parts[0],
        "pipe_id": to_b(parts[1]),
        "session_id": to_n(parts[2]),
        "ntp_time": Dec(parts[3]),
        "predictions": parse_prediction_str(parts[4]),
        "src_addr": parse_peer_addr(to_b(parts[5])),
        "src_addr_bytes": to_b(parts[5]),
        "af": to_n(parts[6]),
        "if": {
            "them": to_n(parts[7]),
            "us": to_n(parts[8])
        }
    }

f_punch_index = lambda ses, addr, pipe: b"%d %b %b" % (ses, addr, pipe)
class P2PPipe():
    def __init__(self, node):
        self.node = node
        self.tasks = []

    # Minor data structure cleanup.
    def cleanup_pipe(self, pipe_id):
        def closure():
            if pipe_id in self.node.pipes:
                del self.node.pipes[pipe_id]

        return closure

    # Waits for a pipe event to fire.
    # Returns the corrosponding pipe.
    async def pipe_waiter(self, pipe_id, timeout=0):
        try:
            pipe_event = self.node.pipe_events[pipe_id]
            if timeout:
                await asyncio.wait_for(
                    pipe_event.wait(),
                    timeout
                )
            else:
                await pipe_event.wait()
            pipe = self.node.pipes[pipe_id]
            return pipe
        except asyncio.TimeoutError:
            log(f"> Pipe waiter timeout {pipe_id} {timeout}")
            return None
        
    # Implements the p2p connection techniques.
    async def open_pipe(self, pipe_id, dest_bytes, strategies=P2P_STRATEGIES):
        log(f"> Pipe open = {pipe_id}; {dest_bytes}; {strategies}")

        # Setup events for waiting on the pipe.
        pipe = None
        p2p_dest = parse_peer_addr(dest_bytes)
        self.node.pipe_events[pipe_id] = asyncio.Event()

        # Patch dest address if it's behind same router.
        dest_patch = work_behind_same_router(self.node.p2p_addr, p2p_dest)
        timeout = 0
        for strategy in strategies:
            # Try connect directly to peer.
            if strategy == P2P_DIRECT:
                timeout = 4
                open_task = self.direct_connect(dest_patch, pipe_id)

            # Tell the peer to try connect to us.
            if strategy == P2P_REVERSE:
                # Associate the pending pipe with external IP(s).
                exts = peer_addr_extract_exts(p2p_dest)
                self.node.expected_addrs[pipe_id] = exts

                # Instruct the peer to do the reverse connect.
                out = build_reverse_msg(pipe_id, self.node.addr_bytes)
                await self.node.signal_pipe.send_msg(
                    out,
                    to_s(p2p_dest["node_id"])
                )

                # Wait for the new pipe to appear.
                timeout = 10
                open_task = self.pipe_waiter(pipe_id)

            # Do TCP hole punching to try connect.
            if strategy == P2P_PUNCH:
                # Start TCP hole punching.
                self.tasks.append(
                    asyncio.create_task(
                        async_wrap_errors(
                            self.tcp_hole_punch(dest_patch, pipe_id)
                        )
                    )
                )

                # Wait for the hole to appear.
                """
                Meet delay = 3
                Punch duration = 3
                Update wait = 4
                Init wait = 4
                Padding = 6
                """
                timeout = 30
                open_task = self.pipe_waiter(pipe_id)

            # Use a TURN server to connect to a peer.
            if strategy == P2P_RELAY:
                timeout = 10
                open_task = self.udp_relay(p2p_dest, pipe_id)

            # Got valid pipe so return it.
            pipe = await async_wrap_errors(open_task, timeout)
            if pipe is not None:
                log(f"> Got pipe = {pipe.sock} from {repr(pipe.route)}.")
                return [pipe, strategy]

        log(f"> Uh oh, pipe was None.")
        return [pipe, None]

    # Main function for scheduling p2p connections.
    async def pipe(self, dest_bytes, timeout=60, strategies=P2P_STRATEGIES):
        # Identify a pipe.
        strategy = p2p_pipe = None
        pipe_id = rand_plain(15)
        assert(isinstance(pipe_id, bytes))

        # Wrap open pipe in a task so it can be cancelled.
        task = asyncio.create_task(
            async_wrap_errors(
                self.open_pipe(pipe_id, dest_bytes, strategies)
            )
        )

        # Record the task in a pending state.
        self.node.pending_pipes[pipe_id] = task
        try:
            await asyncio.wait_for(
                task,
                timeout
            )
            p2p_pipe, strategy = task.result()
        except asyncio.CancelledError:
            log_exception()

        # When it's done delete the pending reference.
        if pipe_id in self.node.pending_pipes:
            del self.node.pending_pipes[pipe_id]
            
        return [p2p_pipe, strategy]

    """
    (1) Connects to every available remote address concurrently.
    (2) Chooses the first connection that succeeds.
    (3) Closes any unneeded connections.
    (4) Only connections to an address if the AF is supported.

                 (currently 3) * (valid af no = ip4, ip6)
    max cons = PEER_ADDR_MAX_INTERFACES * 2 
    """
    async def direct_connect(self, p2p_dest, pipe_id, proto=TCP):
        tasks = []
        out = b"ID %s" % (pipe_id)
        for af in VALID_AFS:
            # Check an interface exists for that AF.
            if not len(self.node.ifs.by_af[af]):
                continue

            # Peer doesn't support af type.
            if not len(p2p_dest[af]):
                continue

            # (1) Get first interface for AF.
            # (2) Build a 'route' from it with it's main NIC IP.
            # (3) Bind to the route at port 0. Return itself.
            route = await self.node.ifs.get(af).route(af).bind()

            # Similar to 'happy eyeballs.'
            for info in p2p_dest[af]:
                # Connect to this address.
                dest = await Address(
                    str(info["ext"]),
                    info["port"]
                ).res(route)

                # Schedule the coroutine.
                tasks.append(
                    pipe_open(
                        route=route,
                        proto=proto,
                        dest=dest,
                        msg_cb=self.node.msg_cb
                    )
                )

        # Do all connections concurrently.
        pipes = await asyncio.gather(*tasks)
        pipes = strip_none(pipes)

        # Only keep the first connection.
        if len(pipes) > 1:
            log("Closing unneeded pipes in direct connect.")
            for i in range(1, len(pipes)):
                await pipes[i].close()

        # On same host recipient needs time to setup con handlers.
        # This prevents race conditions in receiving the con ID.
        await asyncio.sleep(0.1)

        # Send con ID -- used to tell peer which request this relates to.
        if len(pipes):
            log(f"Got pipe in p2p direct {pipes[0].sock}")
            log(f"pipes[0].stream.dest.tup = {pipes[0].stream.dest_tup}")
            log(f"data to send {out}")
            r = await pipes[0].send(out, pipes[0].stream.dest_tup)
            log(f"sending pipe id ret = {r} where 0 is failure.")
            return pipes[0]
        else:
            log("all pipes in direct con returned none.")

        # No cons = failure.
        return None

    """
    Peer A and peer B both have a list of interface info
    for each address family. Each interface connected to
    a unique gateway will have its own NAT characteristics.
    The challenge is to prioritize which combination of
    peer interfaces is most favourable given the interplay
    between their corrosponding NAT qualities.

    The least restrictive NATs are assigned a lower
    value. So the start of the algorithm just groups together
    the lowest value pairs and runs through them until one
    succeeds.
    """
    async def tcp_hole_punch(self, p2p_dest, pipe_id):
        log("In pipe pipe tcp hole punmch.")
        # [af][addr_index] = [[nat_type, if_info], ...]
        nat_pairs = {}

        # Our address and their address will be sorted.
        addr_list = [self.node.p2p_addr, p2p_dest]

        # Check all valid addresses.
        for af in VALID_AFS:
            # Determine if both sides support the AF.
            skip_af = False
            for addr in addr_list:
                if not len(addr[af]):
                    skip_af = True
                    break

            # Skip an AF if both sides don't support it.
            if skip_af:
                log(f"Skipping AF = {af}")
                continue

            # Create a list of NAT types indexed by addr index.
            nat_pairs[af] = {}
            for addr_index, addr in enumerate(addr_list):
                # Store subset of interface details.
                nat_pairs[af][addr_index] = []

                # Loop over all the interface details by address family.
                for _, if_info in enumerate(addr[af]):
                    # Save interface details we're interested in.
                    nat_pairs[af][addr_index].append([
                        if_info["nat"]["type"],
                        if_info
                    ])

                # Sort the details list based on the first field (NAT type.)
                nat_pairs[af][addr_index] = sorted(
                    nat_pairs[af][addr_index],
                    key=lambda x: x[0]
                )

            # Step through interface details for both addresses.
            our_offset = 0
            their_offset = 0
            while 1:
                # List of some interface details for our addr.
                our_info = nat_pairs[af][0][our_offset][1]

                # List of some interface details for their addr.
                their_info = nat_pairs[af][1][their_offset][1]

                # Load info for hole punching.
                if_index = our_info["if_index"]
                interface = self.node.if_list[if_index]
                stun_client = STUNClient(interface=interface, af=af)
                initiator = self.node.tcp_punch_clients[if_index]

                # Calculate punch mode
                route = interface.route(af)
                their_addr = await Address(str(their_info["ext"]), 80).res(route)
                punch_mode = initiator.get_punch_mode(their_addr)

                log(f"Loaded punc mode = {punch_mode}")
                if punch_mode == TCP_PUNCH_REMOTE:
                    use_addr = str(their_info["ext"])
                else:
                    use_addr = str(their_info["nic"])
                log(f"using addr = {use_addr}")
                
                # Step 1 -- set initial mappings for initiator.
                punch_ret = await initiator.proto_send_initial_mappings(
                    use_addr,
                    their_info["nat"],
                    p2p_dest["node_id"],
                    pipe_id,
                    stun_client,
                    mode=punch_mode
                )

                # Build first (required) punch message for peer.
                out = build_punch_response(
                    b"INITIAL_MAPPINGS",
                    pipe_id,
                    punch_ret,
                    self.node.addr_bytes,
                    af,

                    # Which iface we're using from our addr.
                    our_info["if_index"],

                    # Which iface they should use.
                    their_info["if_index"]
                )
                log(f"Sending {out}")

                # Send first protocol signal message to peer.
                send_task = asyncio.create_task(
                    async_wrap_errors(
                        self.node.signal_pipe.send_msg(
                            out,
                            to_s(p2p_dest["node_id"])
                        )
                    )
                )

                # Allow for time to receive updated mappings.
                # Peer checks every 2 seconds.
                try:
                    await asyncio.wait_for(
                        punch_ret[2].wait(),
                        4
                    )
                    log("punch: updated mappings received.")
                except asyncio.TimeoutError:
                    # Updated mappings are not always required.
                    log("punch: timed out getting updated mappings.")
                    pass

                # Start task to get a TCP hole.
                pipe = await get_tcp_hole(
                    PUNCH_INITIATOR,
                    pipe_id,
                    p2p_dest["node_id"],
                    initiator,
                    self.node
                )

                # Exit loops if success.
                if pipe is not None:
                    return pipe

                """
                The next pairing is done by increasing their index by 1.
                If it doesn't point to a new element for them then we're done.
                On the other hand if there is a new element the code
                decides whether to increase our offset indicating there
                are more interfaces to try on our side too.

                It may make sense for every one of their interfaces to
                try punch through to every one of our best interfaces.
                But for now they are only tried once.
                    E.g. m vs m * n
                """
                their_offset += 1

                # Don't increase this if there's no new entry.
                if our_offset < len(nat_pairs[af][0]) - 1:
                    our_offset += 1

                # Exit if their offset exceeds the end.
                if their_offset >= len(nat_pairs[af][1]) - 1:
                    break

    async def udp_relay(self, p2p_dest, pipe_id):
        def load_turn_interface():
            for turn_server in TURN_SERVERS:
                for if_index, interface in enumerate(self.node.if_list):
                    for af in turn_server["afs"]:
                        # Other peer can't handle this address family.
                        if not len(p2p_dest[af]):
                            continue

                        # Interface supports AF.
                        if af in interface.supported():
                            return af, if_index, interface, turn_server

            return None, None, None, None

        # Choose a supported AF, interface, and TURN server.
        af, if_index, interface, turn_server = load_turn_interface()
        if af is None:
            return None

        # Check if a TURN client already exists.
        if self.node.turn_clients[if_index] is not None:
            turn_client = self.node.turn_clients[if_index]
        else:
            # Resolve TURN domain.
            route = await interface.route(af).bind()
            turn_addr = await Address(
                turn_server["host"],
                turn_server["port"]
            ).res(route)

            # Build TURN client.
            turn_client = TURNClient(
                route=route,
                turn_addr=turn_addr,
                turn_user=turn_server["user"],
                turn_pw=turn_server["pass"],
                turn_realm=turn_server["realm"],
                msg_cb=self.node.msg_cb
            )

            # Start TURN client.
            start_task = await turn_client.start()
            self.node.turn_clients[if_index] = turn_client

        # Save the external address to ensure replies are valid.
        self.node.expected_addrs[pipe_id] = [p2p_dest[af][0]["ext"]]

        # Get our tups to send.
        client_tup = await turn_client.client_tup_future
        relay_tup = await turn_client.relay_tup_future

        # Make a source address to send.
        if_index = self.node.if_list.index(interface)
        src_addr_bytes = make_peer_addr(
            self.node.node_id,
            [interface],
            ip=to_b(client_tup[0]),
            port=client_tup[1],
            if_index=if_index
        )

        # Send relay message to peer.
        out = b"TURN_REQUEST %s %d %d %d %s %s %d %s %d %d" % (
            pipe_id,
            af,
            if_index,
            p2p_dest[af][0]["if_index"],
            src_addr_bytes,
            to_b(client_tup[0]),
            int(client_tup[1]),
            to_b(relay_tup[0]),
            int(relay_tup[1]),
            0
        )
        
        # Send out direct con msg using the above addr.
        node_id = to_s(p2p_dest["node_id"])
        turn_client.new_node_event(node_id)
        await self.node.signal_pipe.send_msg(
            to_s(out),
            node_id
        )

        # Return TURN client if it's setup successfully.
        try:
            await asyncio.wait_for(
                turn_client.node_events[node_id].wait(),
                20
            )

            self.node.pipes[pipe_id] = turn_client
            return turn_client
        except asyncio.TimeoutError:
            return None

                
if __name__ == "__main__": # pragma: no cover
    async def test_p2p_con():
        p2p_dest = None
        if1 = await Interface("enp3s0").start()
        if_list = [if1]
        pipe_id = rand_plain(10)
        p2p_pipe = P2PPipe(if_list, 0)
        await p2p_pipe.direct_connect(p2p_dest, pipe_id, proto=TCP)


        while 1:
            await asyncio.sleep(1)

    async_test(test_p2p_con)