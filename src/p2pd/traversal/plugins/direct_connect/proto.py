"""direct_connect protocol message + signal enum + pure-rendezvous handler.

ConIdMsg is a rendezvous notification, not a connection request --
the initiator's already opened the TCP and uses this signal to tell
the responder "the pipe at src_tup belongs to plugin_id X".  The
responder rendezvouses pipe (matched by Node.up_cb in
TraversalManager.inbound_pipes_by_tup) with the plugin_id and
resolves the existing inbound_pipes future the reverse_connect
plugin set up before sending its ConMsg.

Cut-2 of the auto-registration redesign: this used to live as an
isinstance() branch in TraversalManager.recv_signal_msg.  The
plugin loader now picks up PROTO_HANDLERS from main.py and merges
into manager.proto_handlers -- recv_signal_msg looks up by enum
and calls the handler before falling through to plugin-creation,
so non-plugin signals (rendezvous, control frames) don't need
core-protocol changes.
"""
from typing import Any, Dict, Optional

from ....protocol.proto_msg import ProtoMsg
from aionetiface import to_n, to_s


SIG_CON_ID = 9


class ConIdMsg(ProtoMsg):
    """Out-of-band claim from the initiator that an already-open TCP connection
    (identified by the initiator's local socket tuple) belongs to a particular
    plugin_id.
    """

    class Payload(ProtoMsg.Payload):
        """Carries the initiator's view of its own (src_ip, src_port).

        The receiver matches this against client_tup of the recently-accepted
        TCP pipe; same-LAN/loopback paths see identical tuples on both sides
        so the lookup is exact.
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


def handle_con_id(manager: Any, msg: Any) -> None:
    """ConIdMsg rendezvous handler.

    Looks up the freshly-accepted inbound pipe by client_tup in
    manager.inbound_pipes_by_tup and resolves the inbound_pipes
    future that reverse_connect awaits.  When the signal beats the
    accept (rare on LAN, common on slow WAN), register a pending
    claim so up_cb dispatches when the matching pipe lands.
    """
    plugin_id = msg.meta.pipe_id
    src_tup = (msg.payload.src_ip, int(msg.payload.src_port))

    pipe = manager.inbound_pipes_by_tup.pop(src_tup, None)
    if pipe is None:
        manager.pending_con_id_by_tup[src_tup] = plugin_id
        return

    fut = manager.inbound_pipes.get(plugin_id)
    if fut is None:
        return
    if fut.done():
        return
    fut.set_result(pipe)
