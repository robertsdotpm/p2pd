"""turn protocol message.

Plugin-owned. plugin_loader registers TURNMsg under wire name
"turn.TURNMsg" via PROTO_MESSAGES.
"""
from typing import Any, Dict

from ....protocol.proto_msg import ProtoMsg


class TURNMsg(ProtoMsg):
    """Carries TURN relay and peer address tuples for TURN-based connections."""

    class Payload:
        """Contains peer and relay address tuples for a TURN session.

        The initiator picks the TURN server, allocates its own relay,
        and sends the (server identity + relay tuples) to the responder.
        The responder reads server_host/server_port from the payload and
        allocates on the SAME server -- mirroring how reverse_connect
        signals direct_connect targets, instead of the old design where
        both peers independently rendezvous-ranked and hoped to converge.

        server_host / server_port are absent on legacy TURNMsgs from
        peers running pre-handoff code; from_dict treats them as None
        and the receiver falls back to the rendezvous walk.
        """

        def __init__(
            self,
            peer_tup: Any,
            relay_tup: Any,
            server_host: Any = None,
            server_port: Any = None,
        ) -> None:
            self.peer_tup = peer_tup
            self.relay_tup = relay_tup
            self.server_host = server_host
            self.server_port = server_port

        def to_dict(self) -> Dict[str, Any]:
            d = {
                "peer_tup": self.peer_tup,
                "relay_tup": self.relay_tup,
            }
            if self.server_host is not None:
                d["server_host"] = self.server_host
            if self.server_port is not None:
                d["server_port"] = self.server_port
            return d

        @staticmethod
        def from_dict(d: Dict[str, Any]) -> "TURNMsg.Payload":
            return TURNMsg.Payload(
                d["peer_tup"],
                d["relay_tup"],
                d.get("server_host"),
                d.get("server_port"),
            )
