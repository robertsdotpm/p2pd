import json
from ecdsa import VerifyingKey
from aionetiface import *
from sidewire import *
from .signal_defs import *


TCP_PUNCH_LAN = 1
TCP_PUNCH_REMOTE = 2
TCP_PUNCH_SELF = 3


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