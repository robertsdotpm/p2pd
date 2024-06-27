"""
Using offsets for servers is a bad idea as server
lists need to be updated. Use short, unique IDs or
index by host name even if its longer.

- we're not always interested in crafting an entirely
new package e.g. the turn response only switches the
src and dest, and changes the payload
it might make sense to take this into account
"""

import json
from p2pd import *

SIG_P2P_CON = 1
SIG_TCP_PUNCH = 2
SIG_TURN = 3

# TODO: move this somewhere else.
async def get_turn_client(af, serv_id, interface, dest_peer=None, dest_relay=None):
    # TODO: index by id and not offset.
    turn_server = TURN_SERVERS[serv_id]


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
        turn_realm=turn_server["realm"]
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
    
    # Wait for our details.
    peer_tup  = await turn_client.client_tup_future
    relay_tup = await turn_client.relay_tup_future

    # Whitelist a peer if desired.
    if None not in [dest_peer, dest_relay]:
        print("Bob accepting alice.")
        await asyncio.wait_for(
            turn_client.accept_peer(
                dest_peer,
                dest_relay
            ),
            6
        )



    return peer_tup, relay_tup, turn_client

class P2PConMsg():
    def __init__(self, p_node_buf, pipe_id, proto, p_dest_buf):
        # Load fields.
        self.pipe_id = pipe_id
        self.proto = TCP if proto == "TCP" else UDP
        self.p_node_buf = p_node_buf
        self.p_dest_buf = p_dest_buf

        # Validation.
        self.p_node = parse_peer_addr(p_node_buf)
        self.p_dest = parse_peer_addr(p_dest_buf)
        self.p_dest = work_behind_same_router(
            self.p_node,
            self.p_dest,
        )

    @staticmethod
    def unpack(buf, p_node_buf):
        buf = to_s(buf)
        fields = buf.split(" ")
        return P2PConMsg(p_node_buf, *fields)
    
    def pack(self):
        return bytes([SIG_P2P_CON]) + to_b(
            f"{self.pipe_id} {self.proto} "
            f"{self.p_node_buf} {self.p_dest_buf}"
        )
    
class PredictField():
    def __init__(self, mappings):
        self.mappings = mappings

    def pack(self):
        pairs = []
        for pair in self.mappings:
            # remote, reply, local.
            pairs.append(
                b"%d,%d,%d" % (
                    pair[0],
                    pair[1],
                    pair[2]
                )
            )

        return b"|".join(pairs)
    
    @staticmethod
    def unpack(buf):
        buf = to_s(buf)
        predictions = []
        prediction_strs = buf.split("|")
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

        return PredictField(predictions)


# if p_sender_buf != our addr byte
# ... dont proceed

class SigMsg():
    @staticmethod
    def load_addr(af, addr_buf, if_index):
        # Validate src address.
        addr = parse_peer_addr(
            addr_buf
        )

        # Parse af for punching.
        af = to_n(af)
        af = i_to_af(af) 

        # Validate src if index.
        if_len = len(addr[af])
        r = [0, if_len - 1]
        if not in_range(if_index, r):
            raise Exception("bad if_i")
        
        return af, addr

    # Todo: will eventually have sig here too.
    class Integrity():
        pass

    # Information about the message sender.
    class Meta():
        def __init__(self, pipe_id, af, src_buf, src_index):
            # Load meta data about message.
            self.pipe_id = to_s(pipe_id)
            self.src_buf = to_s(src_buf)
            self.src_index = to_n(src_index)
            self.af = af

        def patch_source(self, cur_addr):
            # Parse src_buf to addr.
            self.af, self.src = \
            SigMsg.load_addr(
                self.af,
                self.src_buf,
                self.src_index,
            )

            # Patch addr if needed.
            self.src = work_behind_same_router(
                cur_addr,
                self.src
            )

            # Reference to the network info.
            info = self.src[self.af]
            self.src_info = info[self.src_index]

        def to_dict(self):
            return {
                "pipe_id": self.pipe_id,
                "af": int(self.af),
                "src_buf": self.src_buf,
                "src_index": self.src_index,
            }
        
        @staticmethod
        def from_dict(d):
            return SigMsg.Meta(
                d["pipe_id"],
                d["af"],
                d["src_buf"],
                d["src_index"],
            )

    # The destination node for this msg.
    class Routing():
        def __init__(self, af, dest_buf, dest_index):
            print(dest_buf)
            self.dest_buf = to_s(dest_buf)
            self.dest_index = to_n(dest_index)
            self.af = af
            self.set_cur_dest(dest_buf)
            self.cur_dest_buf = None # set later.

        """
        Peers usually have dynamic addresses.
        The parsed dest will reflect the updated /
        current address of the node that receives this.
        """
        def set_cur_dest(self, cur_dest_buf):
            self.cur_dest_buf = to_s(cur_dest_buf)
            self.af, self.dest = SigMsg.load_addr(
                self.af,
                cur_dest_buf,
                self.dest_index,
            )

            # Reference to the network info.
            info = self.dest[self.af]
            self.dest_info = info[self.dest_index]

        def to_dict(self):
            return {
                "af": int(self.af),
                "dest_buf": self.dest_buf,
                "dest_index": self.dest_index,
            }
        
        @staticmethod
        def from_dict(d):
            return SigMsg.Routing(
                d["af"],
                d["dest_buf"],
                d["dest_index"],
            )

    # Abstract kinda feel.
    class Payload():
        pass

    def __init__(self, data, enum):
        self.meta = SigMsg.Meta.from_dict(
            data["meta"]
        )

        self.routing = SigMsg.Routing.from_dict(
            data["routing"]
        )

        self.payload = self.Payload.from_dict(
            data["payload"]
        )

        self.enum = enum

    def to_dict(self):
        d = {
            "meta": self.meta.to_dict(),
            "routing": self.routing.to_dict(),
            "payload": self.payload.to_dict(),
        }

        return d

    def pack(self):
        return bytes([self.enum]) + \
            to_b(
                json.dumps(
                    self.to_dict()
                )
            )
    
    @classmethod
    def unpack(cls, buf):
        d = json.loads(to_s(buf))
        return cls(d)

    def set_cur_addr(self, cur_addr_buf):
        self.routing.set_cur_dest(cur_addr_buf)

        """
        Update the parsed source addresses to
        point to internal addresses if behind
        the same router.
        """
        self.meta.patch_source(self.routing.dest)

    def switch_src_and_dest(self):
        # Copy all current fields into new object.
        # So that changes don't mutate self.
        x = self.unpack(self.pack()[1:])


        # Swap interface indexes in that object.
        x.meta.src_index = self.routing.dest_index
        x.routing.dest_index = self.meta.src_index

        # Swap src and dest p2p addr in that object.
        x.meta.src_buf = self.routing.cur_dest_buf
        x.routing.dest_buf = self.meta.src_buf

        print(self.routing.cur_dest_buf)
        print(self.meta.src_buf)

        print('x pack = ')
        print(x.pack())

        # Return new object with init on changes.
        return self.unpack(x.pack()[1:])

class TCPPunchMsg(SigMsg):
    # The main contents of this message.
    class Payload():
        def __init__(self, ntp, mappings):
            self.ntp = Dec(ntp)
            self.mappings = mappings

        def to_dict(self):
            return {
                "ntp": str(self.ntp),
                "mappings": self.mappings,
            }
        
        @staticmethod
        def from_dict(d):
            return TCPPunchMsg.Payload(
                d["ntp"],
                d["mappings"],
            )
        
    def __init__(self, data, enum=SIG_TCP_PUNCH):
        super().__init__(data, enum)

class TURNMsg(SigMsg):
    class Payload():
        def __init__(self, peer_tup, relay_tup, serv_id, client_index=-1):
            self.peer_tup = peer_tup
            self.relay_tup = relay_tup
            self.serv_id = serv_id
            self.client_index = client_index

        def to_dict(self):
            return {
                "peer_tup": self.peer_tup,
                "relay_tup": self.relay_tup,
                "serv_id": self.serv_id,
                "client_index": self.client_index,
            }
        
        @staticmethod
        def from_dict(d):
            return TURNMsg.Payload(
                d["peer_tup"],
                d["relay_tup"],
                d["serv_id"],
                d["client_index"]
            )
        
    def __init__(self, data, enum=SIG_TURN):
        super().__init__(data, enum)

class SigProtoHandlers():
    def __init__(self, node):
        self.node = node

    async def handle_con_msg(self, msg):
        # Connect to chosen address.
        p2p_pipe = P2PPipe(self.node)
        pipe = await asyncio.wait_for(
            p2p_pipe.direct_connect(
                msg.p_dest,
                msg.pipe_id,
                proto=msg.proto
            ),
            10
        )
        
        # Setup pipe reference.
        if pipe is not None:
            log("p2p direct in node got a valid pipe.")

            # Record pipe reference.
            self.node.pipes[msg.pipe_id] = pipe

            # Add cleanup callback.
            pipe.add_end_cb(
                self.node.rm_pipe_id(
                    msg.pipe_id
                )
            )

        return pipe
    
    """
    Supports both receiving initial mappings and
    receiving updated mappings by checking state.
    The same message type is used for both which
    avoids code duplication and keeps it simple.
    """
    async def handle_punch_msg(self, msg):
        # AFs must match for this type of message.
        if msg.meta.af != msg.routing.af:
            raise Exception("tcp punch afs differ.")

        # Select our interface.
        iface = self.node.ifs[msg.routing.dest_index]
        punch = self.node.tcp_punch_clients
        punch = punch[msg.routing.dest_index]
        stun  = self.node.stun_clients[0]

        # Wrap their external address.
        dest = await Address(
            str(msg.meta.src_info["ext"]),
            80,
            iface.route(msg.routing.af)
        )

        # Calculate punch mode.
        punch_mode = punch.get_punch_mode(dest)
        if punch_mode == TCP_PUNCH_REMOTE:
            dest = str(msg.meta.src_info["ext"])
        else:
            dest = str(msg.meta.src_info["nic"])

        # Is it initial mappings or updated?
        info = punch.get_state_info(
            msg.meta.src["node_id"],
            msg.meta.pipe_id,
        )

        # Then this is step 2: recipient get mappings.
        if info is None:
            # Get updated mappings for initiator.
            punch_ret = await punch.proto_recv_initial_mappings(
                dest,
                msg.meta.src_info["nat"],
                msg.meta.src["node_id"],
                msg.meta.pipe_id,
                msg.payload.mappings,
                stun,
                msg.payload.ntp,
                mode=punch_mode
            )

            # Schedule the punching meeting.
            self.node.add_punch_meeting([
                msg.routing.dest_index,
                PUNCH_RECIPIENT,
                msg.meta.src["node_id"],
                msg.meta.pipe_id,
            ])

            # Return mappings in a new message.
            reply = msg.switch_src_and_dest()
            reply.payload.mappings = punch_ret[0]
            return reply.pack()
        
        # Then this is optional step 3: update initiator.
        if info is not None:
            # State checks to prevent protocol loops.
            if info["state"] != TCP_PUNCH_IN_MAP:
                return
            
            # Otherwise update the initiator.
            punch_ret = await punch.proto_update_recipient_mappings(
                msg.meta.src["node_id"],
                msg.meta.pipe_id,
                msg.payload.mappings,
                stun
            )

    async def handle_turn_msg(self, msg):
        pass
        # by turn_clients[pipe_id] (optional make)
        # but then accept needs to keep a list of accepted peers in the turn client
        # and i prob need to switch to a laptop with ethernet and wifi...

        # Select our interface.
        iface = self.node.ifs[msg.routing.dest_index]

        # Receive a TURN request.
        if msg.meta.pipe_id not in self.node.turn_clients:
            print("bob recv turn req")
            print(f"{msg.payload.peer_tup} {msg.payload.relay_tup}")
            ret = await get_turn_client(
                msg.routing.af,
                msg.payload.serv_id,
                iface,
                dest_peer=msg.payload.peer_tup,
                dest_relay=msg.payload.relay_tup,
            )
            peer_tup, relay_tup, turn_client = ret
            self.node.turn_clients[msg.meta.pipe_id] = turn_client

            reply = msg.switch_src_and_dest()
            reply.payload.peer_tup = peer_tup
            reply.payload.relay_tup = relay_tup

            return reply

        # Receive a TURN response.
        if msg.meta.pipe_id in self.node.turn_clients:
            # Accept their peer details.
            turn_client = self.node.turn_clients[msg.meta.pipe_id]
            await turn_client.accept_peer(
                msg.payload.peer_tup,
                msg.payload.relay_tup,
            )

    def proto(self, buf):
        p_node = self.node.addr_bytes
        p_addr = self.node.p2p_addr
        node_id = to_s(p_addr["node_id"])
        handler = None
        if buf[0] == SIG_P2P_CON:
            msg = P2PConMsg.unpack(buf[1:], p_node)
            print("got sig p2p dir")
            print(msg)
            return self.handle_con_msg(msg)
        
        if buf[0] == SIG_TCP_PUNCH:
            print("got punch msg")
            msg = TCPPunchMsg.unpack(buf[1:])
            handler = self.handle_punch_msg

        if buf[0] == SIG_TURN:
            print("Got turn msg")
            msg = TURNMsg.unpack(buf[1:])
            handler = self.handle_turn_msg

        if handler is None:
            return

        dest = msg.routing.dest
        if to_s(dest["node_id"]) != node_id:
            print(f"Received message not intended for us. {dest['node_id']} {node_id}")
            return
        
        # Updating routing dest with current addr.
        msg.set_cur_addr(p_node)
        return handler(msg)

"""
Index cons by pipe_id -> future and then
set the future when the con is made.
Then you can await any pipe even if its
made by a more complex process (like punching.)

Maybe a pipe_open improvement.
Then maybe have a queue to process hole punching
meetings in the background.
So you would just do:
    - push to queue
    - await pipe_id

and the background process:
    await queue ...
    do punching
    set pipe future
"""
async def test_proto_rewrite():
    pe = await get_pp_executors()
    #pe2 = await get_pp_executors(workers=2)
    
    if pe is not None:
        qm = multiprocessing.Manager()
    else:
        qm = None

    sys_clock = SysClock(Dec("-0.02839018452552057081653225806"))
    iface = await Interface()
    alice_node = P2PNode([iface])
    bob_node = P2PNode([iface], port=NODE_PORT + 1)
    stun_client = (await get_stun_clients(
        IP4,
        1,
        iface
    ))[0]

    for node in [alice_node, bob_node]:
        node.setup_multiproc(pe, qm)
        node.setup_coordination(sys_clock)
        node.setup_tcp_punching()
        await node.dev()
        node.stun_clients = [stun_client]

    pipe_id = "init_pipe_id"
    delta = delta_info(EQUAL_DELTA, 0)
    their_nat = nat_info(FULL_CONE, delta)
    iface.set_nat(their_nat)

    ##########################################

    pa = SigProtoHandlers(alice_node)
    pb = SigProtoHandlers(bob_node)

    alice_initiator = alice_node.tcp_punch_clients[0]
    bob_recp = bob_node.tcp_punch_clients[0]

    
    route = iface.route(IP4)
    dest = iface.rp[IP4].routes[0].nic()
    dest_addr = await Address(dest, 80, route).res()

    
    af = IP4
    punch_ret = await alice_initiator.proto_send_initial_mappings(
        dest,
        their_nat,
        bob_node.p2p_addr["node_id"],
        pipe_id,
        stun_client,
        mode=TCP_PUNCH_SELF
    )

    print(punch_ret)

    msg = TCPPunchMsg({
        "meta": {
            "pipe_id": pipe_id,
            "af": af,
            "src_buf": alice_node.addr_bytes,
            "src_index": 0,
        },
        "routing": {
            "af": af,
            "dest_buf": bob_node.addr_bytes,
            "dest_index": 0,
        },
        "payload": {
            "ntp": punch_ret[1],
            "mappings": punch_ret[0],
        },
    })

    print(msg)

    """
    Allows enough time for the optional updated
    mappings.
    """

    async def schedule_punching_with_delay(n):
        await asyncio.sleep(n)
        alice_node.add_punch_meeting([
            0,
            PUNCH_INITIATOR,
            bob_node.p2p_addr["node_id"],
            pipe_id,
        ])

    task_sche = asyncio.ensure_future(
        schedule_punching_with_delay(2)
    )

    buf = msg.pack()
    print(buf)

    #print(msg.ntp)
    #print(msg.p_reply_buf)
    #print(alice_node.addr_bytes)



    # Simulate bob receiving initial mappings.
    coro = pb.proto(buf)

    # receive initial mappings msg:
    buf = await coro

    print(buf)


    # simulate alice receive updated mappings msg
    coro = pa.proto(buf)
    await coro
    #await buf

    print(alice_initiator.state)
    print(bob_recp.state)


    bob_hole = await bob_node.pipes[pipe_id]
    alice_hole = await alice_node.pipes[pipe_id]

    print(f"alice hole = {alice_hole}")
    print(f"bob hole = {bob_hole}")

    """
    try:
        results = await asyncio.wait_for(
            asyncio.gather(
                async_wrap_errors(
                    alice_initiator.proto_do_punching(PUNCH_INITIATOR, bob_node.p2p_addr["node_id"], pipe_id)
                ),
                async_wrap_errors(
                    bob_recp.proto_do_punching(PUNCH_RECIPIENT, alice_node.p2p_addr["node_id"], pipe_id)
                )
            ),
            10
        )
    except Exception:
        results = []

    print("Got results = ")
    print(results)
    """


    

    await alice_node.close()
    await bob_node.close()


    return



    msg = P2PConMsg(
        "pipe_id",
        "tcp",
        to_s(node.addr_bytes),
        to_s(node.addr_bytes),
    )

    buf = msg.pack()
    coro = p.proto(buf)
    pipe = await coro
    print("reverse con pipe = ")
    print(pipe)
    if pipe is not None:
        await pipe.close()
    
    print("\n\n\n")
    patched = work_behind_same_router(
        node.p2p_addr, node.p2p_addr
    )

    print(patched)

    await node.close()

async def test_proto_rewrite2():
    # Internode (ethernet)
    alice_iface = await Interface("enp0s25")
    print(alice_iface)

    # Aussie broadband NBN (wifi)
    bob_iface = await Interface("wlx00c0cab5760d")
    print(bob_iface)


    sys_clock = SysClock(Dec("-0.02839018452552057081653225806"))
    alice_node = P2PNode([alice_iface])
    bob_node = P2PNode([bob_iface], port=NODE_PORT + 1)
    af = IP4
    pa = SigProtoHandlers(alice_node)
    pb = SigProtoHandlers(bob_node)


    pipe_id = "turn_pipe_id"
    for node in [alice_node, bob_node]:
        await node.dev()

    # TODO: work on TURN message here.
    # 51.195.101.185

    """
    Todo add sanity check -- is relay addr different to turn serv ip
    is mapped different to our ext?
    """




    alice_peer, alice_relay, alice_turn = await get_turn_client(
        af,
        0,
        alice_iface
    )
    alice_node.turn_clients[pipe_id] = alice_turn

    print(alice_peer)
    print(alice_relay)
    print(alice_turn)


    msg = TURNMsg({
        "meta": {
            "pipe_id": pipe_id,
            "af": af,
            "src_buf": alice_node.addr_bytes,
            "src_index": 0,
        },
        "routing": {
            "af": af,
            "dest_buf": bob_node.addr_bytes,
            "dest_index": 0,
        },
        "payload": {
            "peer_tup": alice_peer,
            "relay_tup": alice_relay,
            "serv_id": 0,
            "client_index": 0,
        },
    }).pack()

    print(msg)

    # Bob gets a turn request.
    coro = pb.proto(msg)
    bob_resp = await coro


    # Alice gets bobs turn response.
    coro = pa.proto(bob_resp.pack())
    resp = await coro

    # Both turn clients ready.

    # Alice sends a msg to bob via their turn client
    msg = b"alice to bob via turn"
    print(f"send to bob relay tup = {bob_resp.payload.relay_tup}")
    print(f"bob client tup {bob_resp.payload.peer_tup}")

    """
    Client will replace bob peer tup with their relay tup
    if it detects that its an accepted client.
    """
    print(alice_turn.peers)
    await alice_turn.send(msg, bob_resp.payload.peer_tup)
    # Allow time for bob to receive the message.
    await asyncio.sleep(2)

    bob_turn = bob_node.turn_clients[pipe_id]
    sub = tup_to_sub(alice_peer)



    recv_msg = await bob_turn.recv(sub, 2)
    print("bob recv msg = ")
    print(bob_turn)
    print(recv_msg)

    """
    if send(... x)
        if x in ... clients, use their relay tup instead for send
    """





    await alice_node.close()
    await bob_node.close()


    return

if __name__ == '__main__':
    async_test(test_proto_rewrite2)

"""
    Signal proto:
        - one big func
        - a case for every 'cmd' ...
        - i/o bound (does io in the func)
        - no checks for bad addrs
        - 

    
"""

