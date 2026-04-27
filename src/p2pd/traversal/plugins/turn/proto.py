"""turn protocol message + signal enum.

Owned by the plugin so plugin_loader can register it via
PROTO_MESSAGES rather than central proto_msg.py edits.
"""
from typing import Any, Dict

from ....protocol.proto_msg import ProtoMsg


SIG_TURN = 3


class TURNMsg(ProtoMsg):
    """Carries TURN relay and peer address tuples for TURN-based connections."""

    class Payload:
        """Contains peer and relay address tuples for a TURN session."""

        def __init__(self, peer_tup: Any, relay_tup: Any) -> None:
            self.peer_tup = peer_tup
            self.relay_tup = relay_tup

        def to_dict(self) -> Dict[str, Any]:
            return {
                "peer_tup": self.peer_tup,
                "relay_tup": self.relay_tup,
            }

        @staticmethod
        def from_dict(d: Dict[str, Any]) -> "TURNMsg.Payload":
            return TURNMsg.Payload(
                d["peer_tup"],
                d["relay_tup"],
            )

    def __init__(self, data: Dict[str, Any], enum: int = SIG_TURN) -> None:
        super().__init__(data, enum)
