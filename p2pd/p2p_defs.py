import json
from .utils import *
from .net import *
from .ip_range import IPRange
from .tcp_punch import TCP_PUNCH_REMOTE, TCP_PUNCH_LAN
from .tcp_punch import TCP_PUNCH_SELF
from .p2p_addr import *

SIG_CON = 1
SIG_TCP_PUNCH = 2
SIG_TURN = 3
P2P_PIPE_CONF = {
    "addr_types": [EXT_BIND, NIC_BIND],
    "return_msg": False,
}

P2P_DIRECT = 1
P2P_REVERSE = 2
P2P_PUNCH = 3
P2P_RELAY = 4

# TURN is not included as a default strategy because it uses UDP.
# It will need a special explanation for the developer.
# SOCKS might be a better protocol for relaying in the future.
P2P_STRATEGIES = [P2P_DIRECT, P2P_REVERSE, P2P_PUNCH]

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