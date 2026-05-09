"""turn protocol message.

Plugin-owned. plugin_loader registers TURNMsg under wire name
"turn.TURNMsg" via PROTO_MESSAGES.
"""

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
            peer_tup,
            relay_tup,
            server_host=None,
            server_port=None,
            tried_servers=None,
            reject_reason=None,
        ):
            self.peer_tup = peer_tup
            self.relay_tup = relay_tup
            self.server_host = server_host
            self.server_port = server_port
            # tried_servers carries every (host, port) the SENDER has
            # already attempted (including ones that succeeded). Receiver
            # merges this into its own local set so neither side picks a
            # server the peer has already excluded -- this is what lets
            # asymmetric-reachability cases (e.g. initiator's mobile
            # carrier reaches a Chinese coturn that the responder's home
            # ISP can't) converge on a mutually-reachable server instead
            # of looping forever.
            self.tried_servers = tried_servers or []
            # reject_reason is set when the SENDER could not allocate on
            # the server it was asked to use. Receiver of a rejection
            # treats it as "pick again, excluding what's now in
            # tried_servers, send me a fresh server choice". Receiver
            # that sees None proceeds with the normal accept-the-relay
            # flow.
            self.reject_reason = reject_reason

        def to_dict(self):
            d = {
                "peer_tup": self.peer_tup,
                "relay_tup": self.relay_tup,
            }
            if self.server_host is not None:
                d["server_host"] = self.server_host
            if self.server_port is not None:
                d["server_port"] = self.server_port
            if self.tried_servers:
                d["tried_servers"] = self.tried_servers
            if self.reject_reason is not None:
                d["reject_reason"] = self.reject_reason
            return d

        @staticmethod
        def from_dict(d):
            return TURNMsg.Payload(
                d["peer_tup"],
                d["relay_tup"],
                d.get("server_host"),
                d.get("server_port"),
                d.get("tried_servers") or [],
                d.get("reject_reason"),
            )
