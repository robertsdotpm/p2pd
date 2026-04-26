"""Traversal signalling protocol message serialisation."""
import json
from typing import Any, Dict, List, Optional, Tuple
from aionetiface import (
    to_s, to_b, to_n, i_to_af, fstr, parse_node_addr, log, IP4, EXT_BIND,
    af_from_ip_s, IPRange,
)
from .proto_defs import (
    SIG_CON,
    SIG_TCP_PUNCH,
    SIG_TURN,
    SIG_GET_ADDR,
    SIG_RETURN_ADDR,
    SIG_DONE,
    SIG_RETRY,
    SIG_RANDOM_PROBE,
    SIG_CON_ID,
    P2P_DIRECT,
    P2P_PUNCH,
    P2P_RELAY,
    P2P_RANDOM_PROBE,
)

TCP_PUNCH_LAN = 1
TCP_PUNCH_REMOTE = 2
TCP_PUNCH_SELF = 3


class ProtoMsg:
    """Base class for all P2P traversal protocol messages."""

    @staticmethod
    def load_addr(af: Any, addr_buf: Any, if_index: int) -> Tuple[Any, Dict[str, Any]]:
        """Parse addr_buf into (af, addr_dict), validating that if_index is present."""
        # Validate src address.
        addr = parse_node_addr(addr_buf)

        # Attach the per-node 127.X.Y.Z loopback alias (computed from the
        # peer's pub_key_hex) onto every if_info so select_dest_ipr /
        # plugin set_routing can reach it as info["loopback"]. The
        # parsed-from-wire addr_map otherwise lacks this field, which
        # would force same-machine traversal off the loopback fast path.
        # Imported locally to keep proto_msg free of a top-level
        # dependency on the node package.
        from ..node.node_utils import enrich_addr_map_with_loopback
        enrich_addr_map_with_loopback(addr)

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
            ttl: int = 0,
            pipe_id: Any = b"",
            af: Any = IP4,
            src_buf: Any = b"",
            src_index: int = 0,
            route_type: Any = EXT_BIND,
            same_machine: bool = False,
            plugin_name: Optional[str] = None,
        ) -> None:
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

        def load_src_addr(self) -> None:
            """Parse src_buf and populate af, src, and src_info on this Meta instance."""
            # Parse src_buf to addr.
            self.af, self.src = ProtoMsg.load_addr(
                self.af,
                self.src_buf,
                self.src_index,
            )

            # Reference to the network info.
            info = self.src[self.af]
            self.src_info = info[self.src_index]

        def to_dict(self) -> Dict[str, Any]:
            """Serialise this Meta to a plain dict suitable for JSON encoding."""
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
        def from_dict(d: Dict[str, Any]) -> "ProtoMsg.Meta":
            """Construct a Meta instance from a plain dict, using safe defaults for missing keys."""
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

        def __init__(self, af: Any = IP4, dest_buf: Any = b"", dest_index: int = 0) -> None:
            self.dest_buf = to_s(dest_buf)
            self.dest_index = to_n(dest_index)
            self.af = af
            if dest_buf:
                self.set_cur_dest(dest_buf)
                self.cur_dest_buf = None  # set later.

        def load_if_extra(self, nics: List[Any]) -> None:
            """Resolve the dest_index to the matching NIC object from the provided list."""
            if_index = self.dest_index
            self.interface = nics[if_index]

        """
        Peers usually have dynamic addresses.
        The parsed dest will reflect the updated /
        current address of the node that receives this.
        """

        def set_cur_dest(self, cur_dest_buf: Any) -> None:
            """Update the destination address from a fresh address buffer and reparse routing info."""
            self.cur_dest_buf = to_s(cur_dest_buf)
            self.af, self.dest = ProtoMsg.load_addr(
                self.af,
                cur_dest_buf,
                self.dest_index,
            )

            # Reference to the network info.
            info = self.dest[self.af]
            self.dest_info = info[self.dest_index]

        def to_dict(self) -> Dict[str, Any]:
            """Serialise this Routing to a plain dict suitable for JSON encoding."""
            return {
                "af": int(self.af),
                "dest_buf": self.dest_buf,
                "dest_index": self.dest_index,
            }

        @staticmethod
        def from_dict(d: Dict[str, Any]) -> "ProtoMsg.Routing":
            """Construct a Routing instance from a plain dict, using safe defaults for missing keys."""
            return ProtoMsg.Routing(
                d.get("af", IP4),
                d.get("dest_buf", b""),
                d.get("dest_index", 0),
            )

    # Abstract kinda feel.
    class Payload:
        """Abstract payload container for protocol message data."""

        def __init__(self) -> None:
            pass

        def to_dict(self) -> Dict[str, Any]:
            """Return an empty dict; subclasses override to include their fields."""
            return {}

        @staticmethod
        def from_dict(d: Dict[str, Any]) -> "ProtoMsg.Payload":
            """Construct an empty Payload; subclasses override to deserialise their fields."""
            return ProtoMsg.Payload()

    def __init__(self, data: Dict[str, Any], enum: int) -> None:
        self.meta = ProtoMsg.Meta.from_dict(data.get("meta", {}))

        self.routing = ProtoMsg.Routing.from_dict(data.get("routing", {}))

        self.payload = self.Payload.from_dict(data.get("payload", {}))

        self.enum = enum

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the full message (meta, routing, payload) to a JSON-compatible dict."""
        d = {
            "meta": self.meta.to_dict(),
            "routing": self.routing.to_dict(),
            "payload": self.payload.to_dict(),
        }

        return d

    def pack(self, sk: Optional[Any] = None) -> bytes:
        """Serialise this message to bytes with the enum prefix followed by JSON payload."""
        return bytes([self.enum]) + to_b(json.dumps(self.to_dict()))

    @classmethod
    def unpack(cls, buf: Any) -> "ProtoMsg":
        """Deserialise bytes (without the leading enum byte) into a ProtoMsg instance."""
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

    def set_cur_addr(self, cur_addr_buf: Any) -> None:
        """Update routing with the current address buffer and set the same-machine flag."""
        self.routing.set_cur_dest(cur_addr_buf)

        # Set same machine flag.
        sid = self.meta.src["machine_id"]
        did = self.routing.dest["machine_id"]
        if sid == did:
            self.meta.same_machine = True


class DoneMsg(ProtoMsg):
    """Signals that traversal is complete and no further messages are needed."""

    def __init__(self, data: Optional[Dict[str, Any]] = None, enum: int = SIG_DONE) -> None:
        super().__init__({}, SIG_DONE)


class RetryMsg(ProtoMsg):
    """Requests the peer to retry the traversal exchange."""

    def __init__(self, data: Optional[Dict[str, Any]] = None, enum: int = SIG_RETRY) -> None:
        super().__init__({}, SIG_RETRY)


class PunchMsg(ProtoMsg):
    """Carries port mapping predictions for TCP hole-punching coordination."""

    # The main contents of this message.
    class Payload:
        """Contains punch mode, NTP timestamp, and port mappings for the punch exchange."""

        def __init__(self, punch_mode: int, ntp: Any, mappings: List[Any]) -> None:
            self.ntp = ntp
            self.mappings = mappings
            self.punch_mode = int(punch_mode)

        def to_dict(self) -> Dict[str, Any]:
            """Serialise the payload to a JSON-compatible dict."""
            return {
                "punch_mode": self.punch_mode,
                "ntp": self.ntp,
                "mappings": self.mappings,
            }

        @staticmethod
        def from_dict(d: Dict[str, Any]) -> "PunchMsg.Payload":
            """Deserialise a dict into a PunchMsg.Payload."""
            return PunchMsg.Payload(
                d.get("punch_mode", TCP_PUNCH_REMOTE),
                d.get("ntp", 0),
                d["mappings"],
            )

    # Note: having the dest the same as an if in our ifs is not
    # necessarily an error if two nodes are on the same
    # computer using the same interfaces. But these
    # checks are left in if they're needed.

    def validate_dest(self, af: Any, punch_mode: int, dest_s: str) -> None:
        """Validate that af, punch_mode, and dest_s are mutually consistent with this message's routing."""
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

            # Punching our own external address?
            # if dest_s == ext:
            #     raise ValueError(fstr("{0} == ext in punch remote", (dest_s,)))

        # Private address sanity checks.
        if punch_mode in [TCP_PUNCH_SELF, TCP_PUNCH_LAN]:
            # Public address indicate for private?
            if ipr.is_public:
                raise ValueError(fstr("{0} is pub for punch $priv", (dest_s,)))

        # Should be another computer's IP.
        # if punch_mode == TCP_PUNCH_LAN:
        #     if dest_s == nic:
        #         raise ValueError(fstr("{0} is ourself for lan punch", (dest_s,)))

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

    def __init__(self, data: Dict[str, Any], enum: int = SIG_TCP_PUNCH) -> None:
        super().__init__(data, enum)


class RandomProbeMsg(ProtoMsg):
    """Carries random-probe rendezvous parameters for symmetric NAT traversal.

    Both sides exchange one of these.  The cone (endpoint-independent)
    side advertises its known external (ip, port).  The symmetric side
    advertises only its external IP -- its outbound port mappings are
    random per-flow and have to be discovered via the probe collision.

    role: "sym" if my own NAT is symmetric, "non_sym" otherwise
          (covers open internet, full cone, restricted, port-
          restricted -- the algorithm only really cares whether
          my outbound port is predictable per flow).
    """

    class Payload:
        """Random-probe payload: rendezvous time, both ext IPs, cone known port, magic."""

        def __init__(
            self,
            role: str,
            punch_time: int,
            magic: str,
            ext_ip: str,
            known_port: int = 0,
            probe_count: int = 256,
        ) -> None:
            self.role = to_s(role)
            self.punch_time = int(punch_time)
            self.magic = to_s(magic)
            self.ext_ip = to_s(ext_ip)
            self.known_port = int(known_port)
            self.probe_count = int(probe_count)

        def to_dict(self) -> Dict[str, Any]:
            """Serialise the payload to a JSON-compatible dict."""
            return {
                "role": self.role,
                "punch_time": self.punch_time,
                "magic": self.magic,
                "ext_ip": self.ext_ip,
                "known_port": self.known_port,
                "probe_count": self.probe_count,
            }

        @staticmethod
        def from_dict(d: Dict[str, Any]) -> "RandomProbeMsg.Payload":
            """Deserialise a dict into a RandomProbeMsg.Payload."""
            return RandomProbeMsg.Payload(
                d.get("role", "non_sym"),
                d.get("punch_time", 0),
                d.get("magic", ""),
                d.get("ext_ip", ""),
                d.get("known_port", 0),
                d.get("probe_count", 256),
            )

    def __init__(self, data: Dict[str, Any], enum: int = SIG_RANDOM_PROBE) -> None:
        super().__init__(data, enum)


class TURNMsg(ProtoMsg):
    """Carries TURN relay and peer address tuples for TURN-based connections."""

    class Payload:
        """Contains peer and relay address tuples for a TURN session."""

        def __init__(self, peer_tup: Any, relay_tup: Any) -> None:
            self.peer_tup = peer_tup
            self.relay_tup = relay_tup

        def to_dict(self) -> Dict[str, Any]:
            """Serialise the payload to a JSON-compatible dict."""
            return {
                "peer_tup": self.peer_tup,
                "relay_tup": self.relay_tup,
            }

        @staticmethod
        def from_dict(d: Dict[str, Any]) -> "TURNMsg.Payload":
            """Deserialise a dict into a TURNMsg.Payload."""
            return TURNMsg.Payload(
                d["peer_tup"],
                d["relay_tup"],
            )

    def __init__(self, data: Dict[str, Any], enum: int = SIG_TURN) -> None:
        super().__init__(data, enum)


class ConMsg(ProtoMsg):
    """Initiates a direct connection attempt between two peers."""

    def __init__(self, data: Optional[Dict[str, Any]] = None, enum: int = SIG_CON) -> None:
        super().__init__(data or {}, enum)


class ConIdMsg(ProtoMsg):
    """Out-of-band claim from the initiator that an already-open TCP connection
    (identified by the initiator's local socket tuple) belongs to a particular
    plugin_id.  Replaces the legacy in-band CON_ID_MSG handshake so node_protocol
    no longer needs to special-case the first datagram on every inbound pipe.
    """

    class Payload(ProtoMsg.Payload):
        """Carries the initiator's view of its own (src_ip, src_port).

        The receiver matches this against client_tup of the recently-accepted
        TCP pipe; same-LAN/loopback paths see identical tuples on both sides
        so the lookup is exact.  When the initiator is behind NAT, the
        receiver's matcher falls back to the peer-pubkey known-IP set
        carried by meta.src_buf.
        """

        def __init__(self, src_ip: str = "", src_port: int = 0) -> None:
            self.src_ip = to_s(src_ip)
            self.src_port = to_n(src_port)

        def to_dict(self) -> Dict[str, Any]:
            return {
                "src_ip": self.src_ip,
                "src_port": self.src_port,
            }

        @staticmethod
        def from_dict(d: Dict[str, Any]) -> "ConIdMsg.Payload":
            return ConIdMsg.Payload(
                d.get("src_ip", ""),
                d.get("src_port", 0),
            )

    def __init__(self, data: Optional[Dict[str, Any]] = None, enum: int = SIG_CON_ID) -> None:
        super().__init__(data or {}, enum)


class GetAddr(ProtoMsg):
    """Requests the current address of the peer node."""

    def __init__(self, data: Optional[Dict[str, Any]] = None, enum: int = SIG_GET_ADDR) -> None:
        super().__init__(data or {}, enum)


class ReturnAddr(ProtoMsg):
    """Returns the sender's address in response to a GetAddr request."""

    def __init__(self, data: Optional[Dict[str, Any]] = None, enum: int = SIG_RETURN_ADDR) -> None:
        super().__init__(data or {}, enum)


SIG_PROTO = {
    SIG_CON: [ConMsg, P2P_DIRECT, 5],
    SIG_TCP_PUNCH: [PunchMsg, P2P_PUNCH, 20],
    SIG_TURN: [TURNMsg, P2P_RELAY, 10],
    SIG_GET_ADDR: [GetAddr, 0, 5],
    SIG_RETURN_ADDR: [ReturnAddr, 0, 6],
    SIG_RANDOM_PROBE: [RandomProbeMsg, P2P_RANDOM_PROBE, 18],
    SIG_CON_ID: [ConIdMsg, P2P_DIRECT, 5],
    # SIG_ADDR: [AddrMsg, 0, 5],
}
