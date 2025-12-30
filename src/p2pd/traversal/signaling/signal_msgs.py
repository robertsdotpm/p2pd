import json
from ecdsa import VerifyingKey
from aionetiface import *
from ..plugins.punch.punch_defs import *
from ...node.node_addr import *
from .signal_defs import *

class SigMsg():
    @staticmethod
    def load_addr(af, addr_buf, if_index):
        # Validate src address.
        addr = parse_node_addr(
            addr_buf
        )

        # Parse af for punching.
        af = to_n(af)
        af = i_to_af(af) 

        # Validate src if index.
        if if_index not in addr[af]:
            raise Exception(fstr("bad if_i {0}", (if_index,)))
        
        return af, addr
    
    class Cipher():
        def __init__(self, vk):
            self.vk = vk

        def to_dict(self):
            return {
                "vk": to_h(self.vk)
            }
        
        @staticmethod
        def from_dict(d):
            vk = d.get("vk", "")
            vk = h_to_b(vk)
            return SigMsg.Cipher(vk)

    # Information about the message sender.
    class Meta():
        def __init__(self, ttl=0, pipe_id=b"", af=IP4, src_buf=b"", src_index=0, route_type=EXT_BIND, same_machine=False, plugin_name=None):
            # Load meta data about message.
            self.ttl = to_n(ttl)
            self.pipe_id = to_s(pipe_id)
            self.src_buf = to_s(src_buf)
            self.src_index = to_n(src_index)
            self.af = af
            self.same_machine = False
            self.route_type = route_type
            self.plugin_name = plugin_name
            if src_buf:
                self.load_src_addr()

        def load_src_addr(self):
            # Parse src_buf to addr.
            self.af, self.src = \
            SigMsg.load_addr(
                self.af,
                self.src_buf,
                self.src_index,
            )

            # Reference to the network info.
            info = self.src[self.af]
            self.src_info = info[self.src_index]

        def to_dict(self):
            return {
                "ttl": self.ttl,
                "pipe_id": self.pipe_id,
                "af": int(self.af),
                "src_buf": self.src_buf,
                "src_index": self.src_index,
                "route_type": self.route_type,
                "same_machine": self.same_machine,
                "plugin_name": self.plugin_name,
            }
        
        @staticmethod
        def from_dict(d):
            return SigMsg.Meta(
                d.get("ttl", 0),
                d.get("pipe_id", b""),
                d.get("af", IP4),
                d.get("src_buf", b""),
                d.get("src_index", 0),
                d.get("route_type", EXT_BIND),
                d.get("same_machine", False),
                d.get("plugin_name", None),
            )

    # The destination node for this msg.
    class Routing():
        def __init__(self, af=IP4, dest_buf=b"", dest_index=0):
            self.dest_buf = to_s(dest_buf)
            self.dest_index = to_n(dest_index)
            self.af = af
            if dest_buf:
                self.set_cur_dest(dest_buf)
                self.cur_dest_buf = None # set later.

        def load_if_extra(self, nics):
            if_index = self.dest_index
            self.interface = nics[if_index]

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
                d.get("dest_buf", b""),
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
            data.get("meta", {})
        )

        self.routing = SigMsg.Routing.from_dict(
            data.get("routing", {})
        )

        self.payload = self.Payload.from_dict(
            data.get("payload", {})
        )

        self.cipher = self.Cipher.from_dict(
            data.get("cipher", {})
        )

        self.enum = enum
            

    def to_dict(self):
        d = {
            "meta": self.meta.to_dict(),
            "routing": self.routing.to_dict(),
            "payload": self.payload.to_dict(),
            "cipher": self.cipher.to_dict(),
        }

        return d

    def pack(self, sk=None):
        return bytes([self.enum]) + \
            to_b(
                json.dumps(
                    self.to_dict()
                )
            )
    
    @classmethod
    def unpack(cls, buf):
        d = json.loads(to_s(buf))

        # Sig checks if set.
        # check node id portion matches pub portion.
        # check sig matches serialized obj.
        return cls(d)

    def set_cur_addr(self, cur_addr_buf):
        self.routing.set_cur_dest(cur_addr_buf)

        # Set same machine flag.
        sid = self.meta.src["machine_id"]
        did = self.routing.dest["machine_id"]
        if sid == did:
            self.meta.same_machine = True

class DoneMsg(SigMsg):
    def __init__(self, data=None, enum=SIG_DONE):
        super().__init__({}, SIG_DONE)

class RetryMsg(SigMsg):
    def __init__(self, data=None, enum=SIG_RETRY):
        super().__init__({}, SIG_RETRY)

class PunchMsg(SigMsg):
    # The main contents of this message.
    class Payload():
        def __init__(self, punch_mode, ntp, mappings):
            self.ntp = ntp
            self.mappings = mappings
            self.punch_mode = int(punch_mode)

        def to_dict(self):
            return {
                "punch_mode": self.punch_mode,
                "ntp": self.ntp,
                "mappings": self.mappings,
            }
        
        @staticmethod
        def from_dict(d):
            return PunchMsg.Payload(
                d.get("punch_mode", TCP_PUNCH_REMOTE),
                d.get("ntp", 0),
                d["mappings"],
            )
        
    """
    Note: having the dest the same as an if in our ifs is not
    necessarily an error if two nodes are on the same
    computer using the same interfaces. But these
    checks are left in if they're needed.
    """
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
                raise Exception(fstr("{0} is priv in punch remote", (dest_s,)))
            
            """
            # Punching our own external address?
            if dest_s == ext:
                raise Exception(f"{dest_s} == ext in punch remote")
            """
            
        # Private address sanity checks.
        if punch_mode in [TCP_PUNCH_SELF, TCP_PUNCH_LAN]:
            # Public address indicate for private?
            if ipr.is_public:
                raise Exception(fstr("{0} is pub for punch $priv", (dest_s,)))
            
        """
        # Should be another computer's IP.
        if punch_mode == TCP_PUNCH_LAN:
            if dest_s == nic:
                raise Exception(f"{dest_s} is ourself for lan punch")
        """
            
        # Should be ourself.
        if punch_mode == TCP_PUNCH_SELF:
            # May be another nic ip.
            if dest_s != nic:
                log(fstr("{0} !ourself {1} in punch self", (dest_s, nic,)))

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
    def __init__(self, data={}, enum=SIG_CON):
        super().__init__(data, enum)

class GetAddr(SigMsg):        
    def __init__(self, data={}, enum=SIG_GET_ADDR):
        super().__init__(data, enum)

class ReturnAddr(SigMsg):        
    def __init__(self, data={}, enum=SIG_RETURN_ADDR):
        super().__init__(data, enum)

SIG_PROTO = {
    SIG_CON: [ConMsg, P2P_DIRECT, 5],
    SIG_TCP_PUNCH: [PunchMsg, P2P_PUNCH, 20],
    SIG_TURN: [TURNMsg, P2P_RELAY, 10],
    SIG_GET_ADDR: [GetAddr, 0, 5],
    SIG_RETURN_ADDR: [ReturnAddr, 0, 6],
    #SIG_ADDR: [AddrMsg, 0, 5],
}