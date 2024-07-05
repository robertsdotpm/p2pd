"""
Using offsets for servers is a bad idea as server
lists need to be updated. Use short, unique IDs or
index by host name even if its longer.

- we're not always interested in crafting an entirely
new package e.g. the turn response only switches the
src and dest, and changes the payload
it might make sense to take this into account

TODO: Add node.msg_cb to pipes started part of 
these methods.
"""

import json
import multiprocessing
from .utils import *
from .settings import *
from .address import *
from .pipe_events import *
from .p2p_addr import *
from .p2p_utils import *
from .tcp_punch import PUNCH_RECIPIENT, PUNCH_INITIATOR
from .tcp_punch import TCP_PUNCH_IN_MAP, get_punch_mode

SIG_CON = 1
SIG_TCP_PUNCH = 2
SIG_TURN = 3


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
            raise Exception("bad if_i {if_index}")
        
        return af, addr

    # Todo: will eventually have sig here too.
    class Integrity():
        pass

    # Information about the message sender.
    class Meta():
        def __init__(self, pipe_id, af, src_buf, src_index=0):
            # Load meta data about message.
            self.pipe_id = to_s(pipe_id)
            self.src_buf = to_s(src_buf)
            self.src_index = to_n(src_index)
            self.af = af
            self.same_machine = False

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
                d.get("pipe_id", rand_plain(15)),
                d.get("af", IP4),
                d["src_buf"],
                d.get("src_index", 0),
            )

    # The destination node for this msg.
    class Routing():
        def __init__(self, af, dest_buf, dest_index=0):
            self.dest_buf = to_s(dest_buf)
            self.dest_index = to_n(dest_index)
            self.af = af
            self.set_cur_dest(dest_buf)
            self.cur_dest_buf = None # set later.

        def load_if_extra(self, node):
            if_index = self.dest_index
            self.interface = node.ifs[if_index]
            self.stun = node.stun_clients[self.af][if_index]
            if if_index in node.tcp_punch_clients:
                self.punch = node.tcp_punch_clients[if_index]
            else:
                self.punch = None

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
                d.get("af", IP4),
                d["dest_buf"],
                d.get("dest_index", 0),
            )

    # Abstract kinda feel.
    class Payload():
        def __init__(self):
            pass

        def to_dict(self):
            return {}
        
        @staticmethod
        def from_dict(d):
            return SigMsg.Payload()

    def __init__(self, data, enum):
        self.meta = SigMsg.Meta.from_dict(
            data["meta"]
        )

        self.routing = SigMsg.Routing.from_dict(
            data["routing"]
        )

        self.payload = self.Payload.from_dict(
            data.get("payload", {})
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

        # Set same machine flag.
        sid = self.meta.src["machine_id"]
        did = self.routing.dest["machine_id"]
        if sid == did:
            self.meta.same_machine = True

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
        def __init__(self, punch_mode, ntp, mappings):
            self.ntp = Dec(ntp)
            self.mappings = mappings
            self.punch_mode = int(punch_mode)

        def to_dict(self):
            return {
                "punch_mode": self.punch_mode,
                "ntp": str(self.ntp),
                "mappings": self.mappings,
            }
        
        @staticmethod
        def from_dict(d):
            return TCPPunchMsg.Payload(
                d.get("punch_mode", TCP_PUNCH_REMOTE),
                d.get("ntp", 0),
                d["mappings"],
            )
        
    def validate_dest(self, af, punch_mode, dest_s):
        # Do we support this af?
        interface = self.routing.interface
        if af not in interface.supported():
            raise Exception("bad af 2 in punch")

        # Does af match dest_s af.
        if af_from_ip_s(dest_s) != af:
            raise Exception("bad af in punch.")

        # Check valid punch mode.
        ext = interface.route(af).ext()
        nic = interface.route(af).nic()
        if punch_mode not in [1, 2, 3]:
            raise Exception("Invalid punch mode")
        
        # Punch mode matches message.
        if punch_mode != self.payload.punch_mode:
            raise Exception("bad punch mode.")
        
        # Remote address checks.
        cidr = af_to_cidr(af)
        ipr = IPRange(dest_s, cidr=cidr)
        if punch_mode == TCP_PUNCH_REMOTE:
            # Private address indicate for remote punching?
            if ipr.is_private:
                raise Exception(f"{dest_s} is priv in punch remote")
            
            # Punching our own external address?
            if dest_s == ext:
                raise Exception(f"{dest_s} == ext in punch remote")
            
        # Private address sanity checks.
        if punch_mode in [TCP_PUNCH_SELF, TCP_PUNCH_LAN]:
            # Public address indicate for private?
            if ipr.is_public:
                raise Exception(f"{dest_s} is pub for punch $priv")
            
        # Should be another computer's IP.
        if punch_mode == TCP_PUNCH_LAN:
            if dest_s == nic:
                raise Exception(f"{dest_s} is ourself for lan punch")
            
        # Should be ourself.
        if punch_mode == TCP_PUNCH_SELF:
            if dest_s != nic:
                raise Exception(f"{dest_s} !ourself in punch self")

    def __init__(self, data, enum=SIG_TCP_PUNCH):
        super().__init__(data, enum)

class TURNMsg(SigMsg):
    class Payload():
        def __init__(self, peer_tup, relay_tup, serv_id):
            self.peer_tup = peer_tup
            self.relay_tup = relay_tup
            self.serv_id = serv_id

        def to_dict(self):
            return {
                "peer_tup": self.peer_tup,
                "relay_tup": self.relay_tup,
                "serv_id": self.serv_id,
            }
        
        @staticmethod
        def from_dict(d):
            return TURNMsg.Payload(
                d["peer_tup"],
                d["relay_tup"],
                d["serv_id"],
            )
        
    def __init__(self, data, enum=SIG_TURN):
        super().__init__(data, enum)

class ConMsg(SigMsg):        
    def __init__(self, data, enum=SIG_CON):
        super().__init__(data, enum)

class SigProtoHandlers():
    def __init__(self, node):
        self.node = node

    async def handle_con_msg(self, msg):
        # Connect to chosen address.
        pipe = await asyncio.wait_for(
            direct_connect(
                msg.meta.pipe_id,
                msg.meta.src_buf,
                self.node,
            ),
            10
        )

        print("Reverse con pipe = ")
        print(pipe)
        print(pipe.sock)
        
        # Setup pipe reference.
        #if pipe is not None:
        #   log("p2p direct in node got a valid pipe.")

            # Record pipe reference.
            #self.node.pipes[msg.pipe_id].set_result(pipe)

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

        # Select [ext or nat] dest and punch mode
        # (either local, self, remote)
        punch = msg.routing.punch
        punch_mode, dest = await get_punch_mode(
            msg.routing.af,
            msg.meta.src_info,
            msg.routing.interface,
            punch,
        )

        # Basic sanity checks on dest.
        # Throws exceptions on error.
        msg.validate_dest(msg.routing.af, punch_mode, dest)

        # Is it initial mappings or updated?
        print("msg meta")
        print(msg.meta.src)
        print(msg.meta.pipe_id)
        print(msg.routing.punch.state)
        print(f"using dest {dest}")
        info = punch.get_state_info(
            msg.meta.src["node_id"],
            msg.meta.pipe_id,
        )

        # Then this is step 2: recipient get mappings.
        if info is None:
            print("recv initial")
            # Get updated mappings for initiator.
            punch_ret = await punch.proto_recv_initial_mappings(
                dest,
                msg.meta.src_info["nat"],
                msg.meta.src["node_id"],
                msg.meta.pipe_id,
                msg.payload.mappings,
                msg.routing.stun,
                msg.payload.ntp,
                mode=punch_mode,
                same_machine=msg.meta.same_machine,
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
            return reply
        
        # Then this is optional step 3: update initiator.
        if info is not None:
            # State checks to prevent protocol loops.
            if info["state"] != TCP_PUNCH_IN_MAP:
                return
            
            print("update mappings")

            
            # Otherwise update the initiator.
            punch_ret = await punch.proto_update_recipient_mappings(
                msg.meta.src["node_id"],
                msg.meta.pipe_id,
                msg.payload.mappings,
                msg.routing.stun,
            )

    async def handle_turn_msg(self, msg):
        # by turn_clients[pipe_id] (optional make)
        # but then accept needs to keep a list of accepted peers in the turn client
        # and i prob need to switch to a laptop with ethernet and wifi...

        # Select our interface.
        iface = self.node.ifs[msg.routing.dest_index]

        # Receive a TURN request.
        if msg.meta.pipe_id not in self.node.turn_clients:
            print("bob recv turn req")
            print(f"{msg.payload.peer_tup} {msg.payload.relay_tup} {msg.payload.serv_id}")
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

    async def proto(self, buf):
        p_node = self.node.addr_bytes
        p_addr = self.node.p2p_addr
        node_id = to_s(p_addr["node_id"])
        handler = None
        if buf[0] == SIG_CON:
            msg = ConMsg.unpack(buf[1:])
            print("got sig p2p dir")
            print(msg)
            handler = self.handle_con_msg
        
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
        msg.routing.load_if_extra(self.node)
        return await handler(msg)

"""
Index cons by pipe_id -> future and then
set the future when the con is made.
Then you can await any pipe even if its
made by a more complex process (like punching.)

Maybe a pipe_open improvement.

"""
async def test_proto_rewrite():
    from .p2p_node import P2PNode
    from .p2p_utils import get_pp_executors, Dec
    from .clock_skew import SysClock
    from .stun_client import get_stun_clients
    from .nat import delta_info, nat_info, EQUAL_DELTA, FULL_CONE
    from .p2p_pipe import P2PPipe
    from .interface import Interface

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
    for node in [alice_node, bob_node]:
        node.setup_multiproc(pe, qm)
        node.setup_coordination(sys_clock)
        node.setup_tcp_punching()
        await node.dev()

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
        alice_node.stun_clients[af][0],
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
            "punch_mode": TCP_PUNCH_SELF,
            "ntp": punch_ret[1],
            "mappings": punch_ret[0],
        },
    })

    print(msg)

    """
    Allows enough time for the optional updated
    mappings.
    """

    task_sche = asyncio.ensure_future(
        alice_node.schedule_punching_with_delay(
            0,
            pipe_id,
            bob_node.p2p_addr["node_id"],
        )
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
    from .p2p_node import P2PNode
    from .p2p_utils import get_pp_executors, Dec
    from .clock_skew import SysClock
    from .stun_client import get_stun_clients
    from .nat import delta_info, nat_info, EQUAL_DELTA, FULL_CONE
    from .p2p_pipe import P2PPipe
    from .interface import Interface
    turn_serv_offset = 1

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
        turn_serv_offset,
        alice_iface
    )
    alice_node.turn_clients[pipe_id] = alice_turn

    print(alice_peer)
    print(alice_relay)
    print(alice_turn)


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
    await alice_turn.send(msg)
    # Allow time for bob to receive the message.
    await asyncio.sleep(2)

    bob_turn = bob_node.turn_clients[pipe_id]
    sub = tup_to_sub(alice_peer)



    recv_msg = await bob_turn.recv()
    print("bob recv msg = ")
    print(bob_turn)
    print(recv_msg)

    """
    if send(... x)
        if x in ... clients, use their relay tup instead for send
    """


    await bob_turn.send(b"bob send turn msg to alice")
    ret = await alice_turn.recv()
    print(f"Alice get resp from bob: {ret}")




    await alice_node.close()
    await bob_node.close()


    return

async def test_proto_rewrite3():
    from .p2p_node import P2PNode
    from .p2p_utils import get_pp_executors, Dec
    from .clock_skew import SysClock
    from .stun_client import get_stun_clients
    from .nat import delta_info, nat_info, EQUAL_DELTA, FULL_CONE
    from .p2p_pipe import P2PPipe
    from .interface import Interface
    pe = await get_pp_executors()
    qm = multiprocessing.Manager()
    sys_clock = SysClock(Dec("-0.02839018452552057081653225806"))

    delta = delta_info(EQUAL_DELTA, 0)
    nat = nat_info(FULL_CONE, delta)

    # Internode (ethernet)
    alice_iface = await Interface("enp0s25")
    alice_iface.set_nat(nat)
    print(alice_iface)

    # Aussie broadband NBN (wifi)
    bob_iface = await Interface("wlx00c0cab5760d")
    bob_iface.set_nat(nat)
    print(bob_iface)

    alice_node = P2PNode([alice_iface])
    bob_node = P2PNode([bob_iface], port=NODE_PORT + 1)
    pa = SigProtoHandlers(alice_node)
    pb = SigProtoHandlers(bob_node)

    for node in [alice_node, bob_node]:
        node.setup_multiproc(pe, qm)
        node.setup_coordination(sys_clock)
        node.setup_tcp_punching()
        await node.dev()

    pipe_id = "init_pipe_id"

    p = P2PPipe(alice_node)
    msg = await p.tcp_hole_punch(pipe_id, bob_node.addr_bytes)
    print(msg)
    print(msg.pack())

    # That's alices side hooked up and working.
    # havent been screwed to do anything else

    # Simulate bob receiving initial mappings.
    coro = pb.proto(msg.pack())
    buf = await coro

    # simulate alice receive updated mappings msg
    #coro = pa.proto(buf)
    #await coro

    bob_hole = await bob_node.pipes[pipe_id]
    alice_hole = await alice_node.pipes[pipe_id]

    print(f"alice hole = {alice_hole}")
    print(f"bob hole = {bob_hole}")


async def test_proto_rewrite4():
    from .p2p_node import P2PNode
    from .p2p_utils import get_pp_executors, Dec
    from .clock_skew import SysClock
    from .stun_client import get_stun_clients
    from .nat import delta_info, nat_info, EQUAL_DELTA, FULL_CONE
    from .p2p_pipe import P2PPipe
    from .interface import Interface
    turn_serv_offset = 1

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

    p = P2PPipe(alice_node)
    msg = (await for_addr_infos(
        pipe_id,
        alice_node.addr_bytes,
        bob_node.addr_bytes,
        p.udp_relay
    )).pack()


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
    alice_turn = alice_node.turn_clients[pipe_id]
    print(alice_turn.peers)
    await alice_turn.send(msg)
    # Allow time for bob to receive the message.
    await asyncio.sleep(2)

    bob_turn = bob_node.turn_clients[pipe_id]



    recv_msg = await bob_turn.recv()
    print("bob recv msg = ")
    print(bob_turn)
    print(recv_msg)

    """
    if send(... x)
        if x in ... clients, use their relay tup instead for send
    """


    await bob_turn.send(b"bob send turn msg to alice")
    ret = await alice_turn.recv()
    print(f"Alice get resp from bob: {ret}")




    await alice_node.close()
    await bob_node.close()


    return

async def test_proto_rewrite5():
    from .p2p_node import P2PNode
    from .p2p_utils import get_pp_executors, Dec
    from .clock_skew import SysClock
    from .stun_client import get_stun_clients
    from .nat import delta_info, nat_info, EQUAL_DELTA, FULL_CONE
    from .p2p_pipe import P2PPipe
    from .interface import Interface
    turn_serv_offset = 1

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

    p = P2PPipe(alice_node)


    msg = ConMsg({
        "meta": {
            "pipe_id": pipe_id,
            "src_buf": alice_node.addr_bytes,
        },
        "routing": {
            "dest_buf": alice_node.addr_bytes,
        },
    })

    # Todo test using different ifaces.
    # improve that logic with the host id idea
    bp = SigProtoHandlers(alice_node)
    coro = bp.proto(msg.pack())
    out = await coro

    print(msg)

    await alice_node.close()
    await bob_node.close()


    return



if __name__ == '__main__':
    async_test(test_proto_rewrite5)

"""
    Signal proto:
        - one big func
        - a case for every 'cmd' ...
        - i/o bound (does io in the func)
        - no checks for bad addrs
        - 

    
"""

