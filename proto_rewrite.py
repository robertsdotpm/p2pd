from p2pd import *

SIG_P2P_CON = 1
SIG_TCP_PUNCH = 2

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
            self.af, self.src = \
            SigMsg.load_addr(
                af,
                self.src_buf,
                self.src_index,
            )

        def to_dict(self):
            return {
                "pipe_id": self.pipe_id,
                "af": int(self.af),
                "src_buf": self.src_buf,
                "src_index": self.src_if_index,
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
            self.af, self.dest = SigMsg.load_addr(
                af,
                self.dest_buf,
                self.dest_index,
            )

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

    def __init__(self, data):
        self.meta = SigMsg.Meta.from_dict(
            data["meta"]
        )

        self.routing = SigMsg.Routing.from_dict(
            data["routing"]
        )

class TCPPunchMsg2(SigMsg):
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
            return TCPPunchMsg2.Payload(
                d["ntp"],
                d["mappings"],
            )

    def __init__(self, data):
        super().__init__(data)
        self.payload = self.Payload.from_dict(
            data["payload"]
        )


    
    pass



class TCPPunchMsg():
    def __init__(self, p_node_buf, af, pipe_id, ntp, predict, p_dest_buf, p_reply_buf, our_index, their_index):
        # Parse af for punching.
        self.af = to_n(af)
        self.af = i_to_af(self.af)        

        # Other params have minimal conversion.
        self.pipe_id = to_s(pipe_id)
        self.ntp = Dec(ntp)
        self.predict = predict
        self.our_index = to_n(our_index)
        self.their_index = to_n(their_index)

        # Convert to peer addr dicts.
        self.p_node_buf = to_s(p_node_buf)
        self.p_dest_buf = to_s(p_dest_buf)
        self.p_reply_buf = to_s(p_reply_buf)
        self.p_reply = parse_peer_addr(p_reply_buf)
        self.p_node = parse_peer_addr(p_node_buf)
        self.p_dest = parse_peer_addr(p_dest_buf)
        self.p_dest = work_behind_same_router(
            self.p_node,
            self.p_dest,
        )

        # Sanity check on their if index.
        r = [0, len(self.p_reply[self.af]) - 1]
        if not in_range(self.their_index, r):
            raise Exception("dest if offset of")
        
        # Reference to their network info.
        info = self.p_reply[self.af]
        self.their_info = info[self.their_index]

    @staticmethod
    def unpack(buf, p_node_buf):
        # Extract serialized fields.
        fields = to_s(buf).split(" ")
        print(fields)
        fields[3] = PredictField.unpack(fields[3])

        return TCPPunchMsg(p_node_buf, *fields)
    
    def pack(self):
        predict = to_s(self.predict.pack())
        return bytes([SIG_TCP_PUNCH]) + to_b(
            f"{self.af} {self.pipe_id} "
            f"{self.ntp} {predict} "
            f"{self.p_dest_buf} {self.p_node_buf} "
            f"{self.our_index} {self.their_index}"
        )

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
    
    async def handle_punch_msg(self, msg):
        # Select our interface.
        iface = self.node.ifs[msg.our_index]
        punch = self.node.tcp_punch_clients
        punch = punch[msg.our_index]
        stun  = self.node.stun_clients[0]

        # Wrap their external address.
        dest = await Address(
            str(msg.their_info["ext"]),
            80,
            iface.route(msg.af)
        )

        # Calculate punch mode.
        punch_mode = punch.get_punch_mode(dest)
        print("punch_mode = ")
        print(punch_mode)

        if punch_mode == TCP_PUNCH_REMOTE:
            dest = str(msg.their_info["ext"])
        else:
            dest = str(msg.their_info["nic"])

        print(f"dest = {dest}")

        # Is it initial mappings or updated?
        info = punch.get_state_info(
            msg.p_reply["node_id"],
            msg.pipe_id,
        )
        if info is None:
            print("in recv init mappings")
            punch_ret = await punch.proto_recv_initial_mappings(
                dest,
                msg.their_info["nat"],
                msg.p_reply["node_id"],
                msg.pipe_id,
                msg.predict.mappings,
                stun,
                msg.ntp,
                mode=punch_mode
            )

            # Send them our mappings.
            return TCPPunchMsg(
                to_s(self.node.addr_bytes),
                msg.af,
                msg.pipe_id,
                msg.ntp,
                PredictField(punch_ret[0]),
                msg.p_reply_buf,
                to_s(self.node.addr_bytes),
                msg.their_index,
                msg.our_index
            ).pack()
        else:
            if info["state"] == TCP_PUNCH_IN_MAP:
                print("in update rec maps")
                punch_ret = await punch.proto_update_recipient_mappings(
                    msg.p_reply["node_id"],
                    msg.pipe_id,
                    msg.predict.mappings,
                    stun
                )


    def proto(self, buf):
        p_node = self.node.addr_bytes
        if buf[0] == SIG_P2P_CON:
            msg = P2PConMsg.unpack(buf[1:], p_node)
            print("got sig p2p dir")
            print(msg)
            return self.handle_con_msg(msg)
        
        if buf[0] == SIG_TCP_PUNCH:
            print("got punch msg")
            msg = TCPPunchMsg.unpack(buf[1:], p_node)
            r = [0, len(self.node.ifs) - 1]
            if not in_range(msg.our_index, r):
                raise Exception("bad if index")
            
            return self.handle_punch_msg(msg)
            print(msg.predict)
            
            print(msg)

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


    """
    Send initial maps from alice to bob:
        msg:
            meta:
                - sender
                - pipe_id

            routing: # dest
                - dest_node_id

            payload:
                - punch_ret


    """

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

    msg = TCPPunchMsg2({
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



    msg = TCPPunchMsg(
        to_s(alice_node.addr_bytes),
        IP4,
        pipe_id,
        punch_ret[1],
        PredictField(punch_ret[0]),
        to_s(bob_node.addr_bytes),
        to_s(alice_node.addr_bytes),
        0,
        0,
    )

    buf = msg.pack()
    print(buf)

    print(msg.ntp)
    print(msg.p_reply_buf)
    print(alice_node.addr_bytes)



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


if __name__ == '__main__':
    async_test(test_proto_rewrite)

"""
    Signal proto:
        - one big func
        - a case for every 'cmd' ...
        - i/o bound (does io in the func)
        - no checks for bad addrs
        - 

    
"""

