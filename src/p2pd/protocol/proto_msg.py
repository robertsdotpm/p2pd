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
from .proto_defs import P2P_DIRECT

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

    # Default WIRE_NAME -- subclasses override with their qualified name
    # (e.g. "tcp_punch.PunchMsg"). The plugin loader auto-derives the
    # qualified form from plugin_name + class.__name__ at install time
    # and patches it onto the class so subclasses don't have to set it
    # by hand. Core messages bake "core.<ClassName>" in directly.
    WIRE_NAME = ""  # type: str

    def __init__(self, data: Dict[str, Any], wire_name: Optional[str] = None) -> None:
        self.meta = ProtoMsg.Meta.from_dict(data.get("meta", {}))

        self.routing = ProtoMsg.Routing.from_dict(data.get("routing", {}))

        self.payload = self.Payload.from_dict(data.get("payload", {}))

        # Per-instance wire_name lets one-off subclasses (UdpPunchMsg
        # over PunchMsg with a different name) override; otherwise the
        # class-level WIRE_NAME is the source of truth.
        self.wire_name = wire_name or self.WIRE_NAME

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the full message (meta, routing, payload) to a JSON-compatible dict."""
        d = {
            "meta": self.meta.to_dict(),
            "routing": self.routing.to_dict(),
            "payload": self.payload.to_dict(),
        }

        return d

    def pack(self, sk: Optional[Any] = None) -> bytes:
        """Serialise this message to bytes with a length-prefixed wire_name + JSON payload.

        Wire layout (after optional encryption framing handled in
        sig_msg_to_buf):

            [name_len: 1 byte][wire_name: ASCII bytes][JSON payload]

        The name is the lookup key for sig_proto_map on the receive
        side -- replacing the old single-byte enum -- so plugins
        never have to coordinate enum allocation: the qualified
        plugin.ClassName is naturally unique by Python's own naming.
        """
        if not self.wire_name:
            raise ValueError(
                "ProtoMsg.pack: wire_name unset -- did the plugin loader run?"
            )
        name_bytes = to_b(self.wire_name)
        if len(name_bytes) > 255:
            raise ValueError(
                "wire_name too long ({0} bytes); max 255".format(len(name_bytes))
            )
        return bytes([len(name_bytes)]) + name_bytes + to_b(json.dumps(self.to_dict()))

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


# Each core message declares its wire name as a class attribute so the
# unpacker's class-by-name lookup hits a stable identifier. Plugin
# messages get their WIRE_NAME patched in by the plugin loader after
# import, derived from the plugin folder name.


class DoneMsg(ProtoMsg):
    """Signals that traversal is complete and no further messages are needed."""

    WIRE_NAME = "core.DoneMsg"

    def __init__(self, data: Optional[Dict[str, Any]] = None) -> None:
        super().__init__({})


class RetryMsg(ProtoMsg):
    """Requests the peer to retry the traversal exchange."""

    WIRE_NAME = "core.RetryMsg"

    def __init__(self, data: Optional[Dict[str, Any]] = None) -> None:
        super().__init__({})


class ConMsg(ProtoMsg):
    """Initiates a direct connection attempt between two peers."""

    WIRE_NAME = "core.ConMsg"

    def __init__(self, data: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(data or {})


class GetAddr(ProtoMsg):
    """Requests the current address of the peer node."""

    WIRE_NAME = "core.GetAddr"

    def __init__(self, data: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(data or {})


class ReturnAddr(ProtoMsg):
    """Returns the sender's address in response to a GetAddr request."""

    WIRE_NAME = "core.ReturnAddr"

    def __init__(self, data: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(data or {})


def build_core_sig_proto() -> Dict[str, list]:
    """Return a fresh dict of CORE (plugin-independent) signal types.

    Keys are wire names ("core.ConMsg", etc.) -- the same name the
    sender writes into the length-prefixed wire framing. Values are
    [msg_class, strategy_enum, ttl_seconds] same as plugin
    PROTO_MESSAGES tuples. plugin_loader merges plugin entries
    (keyed by "<plugin_name>.<MsgClassName>") on top.

    Returning a fresh dict per call (not a module-level constant) keeps
    multiple Routers in the same process from sharing mutable state.
    """
    return {
        ConMsg.WIRE_NAME: [ConMsg, P2P_DIRECT, 5],
        GetAddr.WIRE_NAME: [GetAddr, 0, 5],
        ReturnAddr.WIRE_NAME: [ReturnAddr, 0, 6],
        DoneMsg.WIRE_NAME: [DoneMsg, 0, 5],
        RetryMsg.WIRE_NAME: [RetryMsg, 0, 5],
    }
