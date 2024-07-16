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
from .interface import select_if_by_dest

SIG_CON = 1
SIG_TCP_PUNCH = 2
SIG_TURN = 3
P2P_PIPE_CONF = {
    "addr_types": [EXT_BIND, NIC_BIND],
    "return_msg": False,
}

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
        def __init__(self, pipe_id, af, src_buf, src_index=0, addr_types=[EXT_BIND, NIC_BIND]):
            # Load meta data about message.
            self.pipe_id = to_s(pipe_id)
            self.src_buf = to_s(src_buf)
            self.src_index = to_n(src_index)
            self.af = af
            self.same_machine = False
            self.addr_types = addr_types

        def patch_source(self, cur_addr):
            # Parse src_buf to addr.
            self.af, self.src = \
            SigMsg.load_addr(
                self.af,
                self.src_buf,
                self.src_index,
            )

            self.cur_addr = cur_addr

            # Reference to the network info.
            info = self.src[self.af]
            self.src_info = info[self.src_index]

        def to_dict(self):
            return {
                "pipe_id": self.pipe_id,
                "af": int(self.af),
                "src_buf": self.src_buf,
                "src_index": self.src_index,
                "addr_types": self.addr_types,
            }
        
        @staticmethod
        def from_dict(d):
            return SigMsg.Meta(
                d["pipe_id"],
                d.get("af", IP4),
                d["src_buf"],
                d.get("src_index", 0),
                d.get("addr_types", [EXT_BIND, NIC_BIND]),
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
            try:
                self.punch = node.tcp_punch_clients[if_index]
            except IndexError:
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
            # May be another nic ip.
            if dest_s != nic:
                log(f"{dest_s} !ourself {nic} in punch self")

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
    def __init__(self, node, conf=P2P_PIPE_CONF):
        self.node = node
        self.seen = {}
        self.conf = conf

    async def handle_con_msg(self, msg, conf):
        # Connect to chosen address.
        pp = self.node.p2p_pipe(
            msg.meta.src_buf,
            reply=msg,
            conf=conf,
        )

        # Connect to chosen address.
        await asyncio.wait_for(
            pp.connect(strategies=[P2P_DIRECT]),
            5
        )
    
    """
    Supports both receiving initial mappings and
    receiving updated mappings by checking state.
    The same message type is used for both which
    avoids code duplication and keeps it simple.
    """
    async def handle_punch_msg(self, msg, conf):
        print(msg.pack())
        pp = self.node.p2p_pipe(
            msg.meta.src_buf,
            reply=msg,
            conf=conf,
        )

        # Connect to chosen address.
        pipe = await asyncio.wait_for(
            pp.connect(strategies=[P2P_PUNCH]),
            10
        )

        print("handle punch pipe = ")
        print(pipe)
        return

    async def handle_turn_msg(self, msg, conf):
        print("in handle turn msg")
        pp = self.node.p2p_pipe(
            msg.meta.src_buf,
            reply=msg,
            conf=conf,
        )

        # Connect to chosen address.
        msg = await asyncio.wait_for(
            pp.connect(strategies=[P2P_RELAY]),
            10
        )

        return msg

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
        
        # Reject already processed.
        if msg.meta.pipe_id in self.seen:
            print("in seen")
            return
        else:
            self.seen[msg.meta.pipe_id] = 1

        conf = dict_child({
            "addr_types": msg.meta.addr_types
        }, self.conf)

        
        # Updating routing dest with current addr.
        assert(msg is not None)
        msg.set_cur_addr(p_node)
        msg.routing.load_if_extra(self.node)
        
        return await handler(msg, conf)
    
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
        pipe_id = to_s(parts[1])
        if pipe_id not in self.pipes:
            pass
            self.pipe_future(self.pipe_id)


        if pipe_id in self.pipes:
            log(f"pipe = '{pipe_id}' not in pipe events. saving.")
            self.pipe_ready(pipe_id, pipe)


"""
Index cons by pipe_id -> future and then
set the future when the con is made.
Then you can await any pipe even if its
made by a more complex process (like punching.)

Maybe a pipe_open improvement.

"""


if __name__ == '__main__':
    pass
    #async_test(test_proto_rewrite5)

"""
    Signal proto:
        - one big func
        - a case for every 'cmd' ...
        - i/o bound (does io in the func)
        - no checks for bad addrs
        - 

    
"""

