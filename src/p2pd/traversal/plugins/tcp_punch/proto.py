"""tcp_punch protocol message.

Owned by the plugin so the central protocol layer doesn't need to
import / register tcp_punch-specific types. plugin_loader picks up
PROTO_MESSAGES from main.py and merges PunchMsg into the running
TraversalManager.sig_proto under the wire name "tcp_punch.PunchMsg".

No more SIG enum number to coordinate -- the plugin folder name +
class name uniquely identifies the type on the wire. The plugin
loader patches WIRE_NAME onto the class at install time.
"""

from ....protocol.proto_msg import ProtoMsg


# Punch-mode discriminators -- application-level, NOT wire-level.
# Stay here because they only apply to the punch exchange but are
# referenced from the engine.
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

        def __init__(self, punch_mode, ntp, mappings, nonce=""):
            self.ntp = ntp
            self.mappings = mappings
            self.punch_mode = int(punch_mode)
            self.nonce = nonce

        def to_dict(self):
            return {
                "punch_mode": self.punch_mode,
                "ntp": self.ntp,
                "mappings": self.mappings,
                "nonce": self.nonce,
            }

        @staticmethod
        def from_dict(d):
            return PunchMsg.Payload(
                d.get("punch_mode", TCP_PUNCH_REMOTE),
                d.get("ntp", 0),
                d["mappings"],
                d.get("nonce", ""),
            )
