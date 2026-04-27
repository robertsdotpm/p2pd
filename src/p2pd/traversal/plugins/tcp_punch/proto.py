"""tcp_punch protocol message + signal enum.

Owned by the plugin so the central protocol layer doesn't need to
import / register tcp_punch-specific types. plugin_loader picks up
the PROTO_MESSAGES tuple in main.py and merges it into the running
TraversalManager.sig_proto dict.

Wire enum lives here as the authoritative source -- proto_defs.py
re-exports a flat allocation table for collision detection at
load time, but the plugin owns the actual constant.
"""
from typing import Any, Dict, List, Optional

from ....protocol.proto_msg import ProtoMsg


# tcp_punch claims signal slot 2 historically. Keep the literal here
# so the plugin folder is self-contained; proto_defs.py re-exports it
# for the cross-plugin collision check the loader does.
SIG_TCP_PUNCH = 2

# Punch-mode discriminators. Local to the protocol since they only
# apply to the punch exchange, but referenced from the engine.
TCP_PUNCH_LAN = 1
TCP_PUNCH_REMOTE = 2
TCP_PUNCH_SELF = 3


class PunchMsg(ProtoMsg):
    """Carries port mapping predictions for TCP hole-punching coordination."""

    class Payload:
        """Contains punch mode, NTP timestamp, and port mappings for the punch exchange.

        nonce is optional and only set by udp_punch (where the engine
        needs an app-level token to distinguish real arrivals from
        random scanner traffic on the predicted port). tcp_punch leaves
        it empty; the receiver tolerates either case.
        """

        def __init__(self, punch_mode: int, ntp: Any, mappings: List[Any], nonce: str = "") -> None:
            self.ntp = ntp
            self.mappings = mappings
            self.punch_mode = int(punch_mode)
            self.nonce = nonce

        def to_dict(self) -> Dict[str, Any]:
            return {
                "punch_mode": self.punch_mode,
                "ntp": self.ntp,
                "mappings": self.mappings,
                "nonce": self.nonce,
            }

        @staticmethod
        def from_dict(d: Dict[str, Any]) -> "PunchMsg.Payload":
            return PunchMsg.Payload(
                d.get("punch_mode", TCP_PUNCH_REMOTE),
                d.get("ntp", 0),
                d["mappings"],
                d.get("nonce", ""),
            )

    def __init__(self, data: Dict[str, Any], enum: int = SIG_TCP_PUNCH) -> None:
        super().__init__(data, enum)
