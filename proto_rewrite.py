"""
Using offsets for servers is a bad idea as server
lists need to be updated. Use short, unique IDs or
index by host name even if its longer.
"""

import json
from p2pd import *

SIG_P2P_CON = 1
SIG_TCP_PUNCH = 2
SIG_TURN = 3

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
            self.dest_buf = to_s(dest_buf)
            self.dest_index = to_n(dest_index)
            self.af = af
            self.set_cur_dest(dest_buf)

        """
        Peers usually have dynamic addresses.
        The parsed dest will reflect the updated /
        current address of the node that receives this.
        """
        def set_cur_dest(self, cur_dest_buf):
            self.cur_dest_buf = cur_dest_buf
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
        
        def pack(self):
            return bytes([SIG_TCP_PUNCH]) + \
                to_b(
                    json.dumps(
                        self.to_dict()
                    )
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
            return TCPPunchMsg({
                # Reuse same pipe and desired AF.
                # Pass our details here.
                "meta": {
                    "pipe_id": msg.meta.pipe_id,
                    "af": msg.routing.af,
                    "src_buf": self.node.addr_bytes,
                    "src_index": msg.routing.dest_index,
                },

                # The message sender is now the dest.
                "routing": {
                    "af": msg.routing.af,
                    "dest_buf": msg.meta.src_buf,
                    "dest_index": msg.meta.src_index,
                },

                # Reuse the same NTP but pass our mappings.
                "payload": {
                    "ntp": msg.payload.ntp,
                    "mappings": punch_ret[0],
                },
            }).pack()
        
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

    def proto(self, buf):
        p_node = self.node.addr_bytes
        p_addr = self.node.p2p_addr
        node_id = to_s(p_addr["node_id"])
        if buf[0] == SIG_P2P_CON:
            msg = P2PConMsg.unpack(buf[1:], p_node)
            print("got sig p2p dir")
            print(msg)
            return self.handle_con_msg(msg)
        
        if buf[0] == SIG_TCP_PUNCH:
            print("got punch msg")
            msg = TCPPunchMsg.unpack(buf[1:])
            dest = msg.routing.dest
            if to_s(dest["node_id"]) != node_id:
                print(f"Received message not intended for us. {dest['node_id']} {node_id}")
                return
            
            # Updating routing dest with current addr.
            msg.set_cur_addr(p_node)
            return self.handle_punch_msg(msg)
            print(msg.predict)
            
            print(msg)

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
    sys_clock = SysClock(Dec("-0.02839018452552057081653225806"))
    iface = await Interface()
    alice_node = P2PNode([iface])
    bob_node = P2PNode([iface], port=NODE_PORT + 1)
    af = IP4
    stun_client = (await get_stun_clients(
        af,
        1,
        iface
    ))[0]


    pipe_id = "turn_pipe_id"
    for node in [alice_node, bob_node]:
        await node.dev()

    # TODO: work on TURN message here.

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
            await asyncio.wait_for(
                turn_client.accept_peer(
                    dest_peer,
                    dest_relay
                ),
                6
            )

        return peer_tup, relay_tup, turn_client


    alice_peer, alice_relay, alice_turn = await get_turn_client(
        af,
        0,
        iface
    )

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
    })

    print(msg)





    await alice_turn.close()
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

