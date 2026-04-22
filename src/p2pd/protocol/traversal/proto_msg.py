import json
from aionetiface import *
from sidewire import *
from .proto_defs import *

TCP_PUNCH_LAN = 1
TCP_PUNCH_REMOTE = 2
TCP_PUNCH_SELF = 3


class ProtoMsg:
    """Base class for all P2P traversal protocol messages."""

    @staticmethod
    def load_addr(af, addr_buf, if_index):
        # type: (Any, Any, int) -> Tuple[Any, Dict[str, Any]]
        # Validate src address.
        addr = parse_node_addr(addr_buf)

        # Parse af for punching.
        af = to_n(af)
        af = i_to_af(af)

        # Validate src if index.
        if if_index not in addr[af]:
            raise ValueError(fstr("bad if_i {0}", (if_index,)))

        return af, addr

    # Information about the message sender.
    class Meta:
        """Holds metadata about the sender of a protocol message."""

        def __init__(
            self,
            ttl=0,
            pipe_id=b"",
            af=IP4,
            src_buf=b"",
            src_index=0,
            route_type=EXT_BIND,
            same_machine=False,
            plugin_name=None,
        ):
            # type: (int, Any, Any, Any, int, Any, bool, Optional[str]) -> None
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
            # type: () -> None
            # Parse src_buf to addr.
            self.af, self.src = ProtoMsg.load_addr(
                self.af,
                self.src_buf,
                self.src_index,
            )

            # Reference to the network info.
            info = self.src[self.af]
            self.src_info = info[self.src_index]

        def to_dict(self):
            # type: () -> Dict[str, Any]
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
            # type: (Dict[str, Any]) -> ProtoMsg.Meta
            return ProtoMsg.Meta(
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
    class Routing:
        """Encapsulates destination routing information for a protocol message."""

        def __init__(self, af=IP4, dest_buf=b"", dest_index=0):
            # type: (Any, Any, int) -> None
            self.dest_buf = to_s(dest_buf)
            self.dest_index = to_n(dest_index)
            self.af = af
            if dest_buf:
                self.set_cur_dest(dest_buf)
                self.cur_dest_buf = None  # set later.

        def load_if_extra(self, nics):
            # type: (List[Any]) -> None
            if_index = self.dest_index
            self.interface = nics[if_index]

        """
        Peers usually have dynamic addresses.
        The parsed dest will reflect the updated /
        current address of the node that receives this.
        """

        def set_cur_dest(self, cur_dest_buf):
            # type: (Any) -> None
            self.cur_dest_buf = to_s(cur_dest_buf)
            self.af, self.dest = ProtoMsg.load_addr(
                self.af,
                cur_dest_buf,
                self.dest_index,
            )

            # Reference to the network info.
            info = self.dest[self.af]
            self.dest_info = info[self.dest_index]

        def to_dict(self):
            # type: () -> Dict[str, Any]
            return {
                "af": int(self.af),
                "dest_buf": self.dest_buf,
                "dest_index": self.dest_index,
            }

        @staticmethod
        def from_dict(d):
            # type: (Dict[str, Any]) -> ProtoMsg.Routing
            return ProtoMsg.Routing(
                d.get("af", IP4),
                d.get("dest_buf", b""),
                d.get("dest_index", 0),
            )

    # Abstract kinda feel.
    class Payload:
        """Abstract payload container for protocol message data."""

        def __init__(self):
            # type: () -> None
            pass

        def to_dict(self):
            # type: () -> Dict[str, Any]
            return {}

        @staticmethod
        def from_dict(d):
            # type: (Dict[str, Any]) -> ProtoMsg.Payload
            return ProtoMsg.Payload()

    def __init__(self, data, enum):
        # type: (Dict[str, Any], int) -> None
        self.meta = ProtoMsg.Meta.from_dict(data.get("meta", {}))

        self.routing = ProtoMsg.Routing.from_dict(data.get("routing", {}))

        self.payload = self.Payload.from_dict(data.get("payload", {}))

        self.enum = enum

    def to_dict(self):
        # type: () -> Dict[str, Any]
        d = {
            "meta": self.meta.to_dict(),
            "routing": self.routing.to_dict(),
            "payload": self.payload.to_dict(),
        }

        return d

    def pack(self, sk=None):
        # type: (Optional[Any]) -> bytes
        return bytes([self.enum]) + to_b(json.dumps(self.to_dict()))

    @classmethod
    def unpack(cls, buf):
        # type: (Any) -> ProtoMsg
        try:
            d = json.loads(to_s(buf))
        except (ValueError, UnicodeDecodeError) as e:
            raise ValueError(
                fstr("SigMsg.unpack: malformed payload ({0}): {1!r}", (e, buf[:80]))
            ) from e

        # Sig checks if set.
        # check node id portion matches pub portion.
        # check sig matches serialized obj.
        return cls(d)

    def set_cur_addr(self, cur_addr_buf):
        # type: (Any) -> None
        self.routing.set_cur_dest(cur_addr_buf)

        # Set same machine flag.
        sid = self.meta.src["machine_id"]
        did = self.routing.dest["machine_id"]
        if sid == did:
            self.meta.same_machine = True


class DoneMsg(ProtoMsg):
    """Signals that traversal is complete and no further messages are needed."""

    def __init__(self, data=None, enum=SIG_DONE):
        # type: (Optional[Dict[str, Any]], int) -> None
        super().__init__({}, SIG_DONE)


class RetryMsg(ProtoMsg):
    """Requests the peer to retry the traversal exchange."""

    def __init__(self, data=None, enum=SIG_RETRY):
        # type: (Optional[Dict[str, Any]], int) -> None
        super().__init__({}, SIG_RETRY)


class PunchMsg(ProtoMsg):
    """Carries port mapping predictions for TCP hole-punching coordination."""

    # The main contents of this message.
    class Payload:
        """Contains punch mode, NTP timestamp, and port mappings for the punch exchange."""

        def __init__(self, punch_mode, ntp, mappings):
            # type: (int, Any, List[Any]) -> None
            self.ntp = ntp
            self.mappings = mappings
            self.punch_mode = int(punch_mode)

        def to_dict(self):
            # type: () -> Dict[str, Any]
            return {
                "punch_mode": self.punch_mode,
                "ntp": self.ntp,
                "mappings": self.mappings,
            }

        @staticmethod
        def from_dict(d):
            # type: (Dict[str, Any]) -> PunchMsg.Payload
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
        # type: (Any, int, str) -> None
        # Do we support this af?
        interface = self.routing.interface
        if af not in interface.supported():
            raise ValueError("bad af 2 in punch")

        # Does af match dest_s af.
        if af_from_ip_s(dest_s) != af:
            raise ValueError("bad af in punch.")

        # Check valid punch mode.
        nic = interface.route(af).nic()
        if punch_mode not in [1, 2, 3]:
            raise ValueError("Invalid punch mode")

        # Punch mode matches message.
        if punch_mode != self.payload.punch_mode:
            raise ValueError("bad punch mode.")

        # Remote address checks.
        host_limit = 0
        ipr = IPRange(dest_s, bitlen=host_limit)
        if punch_mode == TCP_PUNCH_REMOTE:
            # Private address indicate for remote punching?
            if ipr.is_private:
                raise ValueError(fstr("{0} is priv in punch remote", (dest_s,)))

            """
            # Punching our own external address?
            if dest_s == ext:
                raise ValueError(f"{dest_s} == ext in punch remote")
            """

        # Private address sanity checks.
        if punch_mode in [TCP_PUNCH_SELF, TCP_PUNCH_LAN]:
            # Public address indicate for private?
            if ipr.is_public:
                raise ValueError(fstr("{0} is pub for punch $priv", (dest_s,)))

        """
        # Should be another computer's IP.
        if punch_mode == TCP_PUNCH_LAN:
            if dest_s == nic:
                raise ValueError(f"{dest_s} is ourself for lan punch")
        """

        # Should be ourself.
        if punch_mode == TCP_PUNCH_SELF:
            # May be another nic ip.
            if dest_s != nic:
                log(
                    fstr(
                        "{0} !ourself {1} in punch self",
                        (
                            dest_s,
                            nic,
                        ),
                    )
                )

    def __init__(self, data, enum=SIG_TCP_PUNCH):
        # type: (Dict[str, Any], int) -> None
        super().__init__(data, enum)


class TURNMsg(ProtoMsg):
    """Carries TURN relay and peer address tuples for TURN-based connections."""

    class Payload:
        """Contains peer and relay address tuples for a TURN session."""

        def __init__(self, peer_tup, relay_tup):
            # type: (Any, Any) -> None
            self.peer_tup = peer_tup
            self.relay_tup = relay_tup

        def to_dict(self):
            # type: () -> Dict[str, Any]
            return {
                "peer_tup": self.peer_tup,
                "relay_tup": self.relay_tup,
            }

        @staticmethod
        def from_dict(d):
            # type: (Dict[str, Any]) -> TURNMsg.Payload
            return TURNMsg.Payload(
                d["peer_tup"],
                d["relay_tup"],
            )

    def __init__(self, data, enum=SIG_TURN):
        # type: (Dict[str, Any], int) -> None
        super().__init__(data, enum)


class ConMsg(ProtoMsg):
    """Initiates a direct connection attempt between two peers."""

    def __init__(self, data=None, enum=SIG_CON):
        # type: (Optional[Dict[str, Any]], int) -> None
        super().__init__(data or {}, enum)


class GetAddr(ProtoMsg):
    """Requests the current address of the peer node."""

    def __init__(self, data=None, enum=SIG_GET_ADDR):
        # type: (Optional[Dict[str, Any]], int) -> None
        super().__init__(data or {}, enum)


class ReturnAddr(ProtoMsg):
    """Returns the sender's address in response to a GetAddr request."""

    def __init__(self, data=None, enum=SIG_RETURN_ADDR):
        # type: (Optional[Dict[str, Any]], int) -> None
        super().__init__(data or {}, enum)


SIG_PROTO = {
    SIG_CON: [ConMsg, P2P_DIRECT, 5],
    SIG_TCP_PUNCH: [PunchMsg, P2P_PUNCH, 20],
    SIG_TURN: [TURNMsg, P2P_RELAY, 10],
    SIG_GET_ADDR: [GetAddr, 0, 5],
    SIG_RETURN_ADDR: [ReturnAddr, 0, 6],
    # SIG_ADDR: [AddrMsg, 0, 5],
}
