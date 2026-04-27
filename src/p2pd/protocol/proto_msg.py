"""Traversal signalling protocol message serialisation.

Core, plugin-independent message types (ConMsg, GetAddr, ReturnAddr,
DoneMsg, RetryMsg) and the abstract ProtoMsg + Meta + Routing + Payload
base classes live here. Plugin-owned message types (PunchMsg, TURNMsg,
RandomProbeMsg, ConIdMsg, UdpPunchMsg) live in each plugin's own
proto.py and auto-register via PROTO_MESSAGES on plugin load -- see
plugin_loader.py and TraversalManager.sig_proto.
"""
import json
from typing import Any, Dict, List, Optional, Tuple
from aionetiface import (
    to_s, to_b, to_n, i_to_af, fstr, parse_node_addr, log, IP4, EXT_BIND,
    af_from_ip_s, IPRange,
)
from .proto_defs import (
    SIG_CON,
    SIG_GET_ADDR,
    SIG_RETURN_ADDR,
    SIG_DONE,
    SIG_RETRY,
    P2P_DIRECT,
)

# Backwards compat: a couple of legacy callers still reference these
# from this module. Defining them here as plain ints means we don't
# break the import while the migration to plugin-owned proto.py
# completes. Once those callers are updated to import from the
# tcp_punch.proto module these can be deleted.
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


class ConMsg(ProtoMsg):
    """Initiates a direct connection attempt between two peers."""

    def __init__(self, data: Optional[Dict[str, Any]] = None, enum: int = SIG_CON) -> None:
        super().__init__(data or {}, enum)


class GetAddr(ProtoMsg):
    """Requests the current address of the peer node."""

    def __init__(self, data: Optional[Dict[str, Any]] = None, enum: int = SIG_GET_ADDR) -> None:
        super().__init__(data or {}, enum)


class ReturnAddr(ProtoMsg):
    """Returns the sender's address in response to a GetAddr request."""

    def __init__(self, data: Optional[Dict[str, Any]] = None, enum: int = SIG_RETURN_ADDR) -> None:
        super().__init__(data or {}, enum)


def build_core_sig_proto() -> Dict[int, list]:
    """Return a fresh dict of CORE (plugin-independent) signal types.

    Each value is [msg_class, strategy_enum, ttl_seconds] -- same shape
    plugins use in their PROTO_MESSAGES tuples. The traversal manager
    seeds self.sig_proto with this and plugin_loader merges
    PROTO_MESSAGES from each plugin's main.py on top, producing the
    runtime sig_proto dispatch table.

    Returning a fresh dict per call (not a module-level constant) keeps
    multiple Routers in the same process from sharing mutable state.
    """
    return {
        SIG_CON: [ConMsg, P2P_DIRECT, 5],
        SIG_GET_ADDR: [GetAddr, 0, 5],
        SIG_RETURN_ADDR: [ReturnAddr, 0, 6],
    }
