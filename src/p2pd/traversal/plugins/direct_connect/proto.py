"""direct_connect protocol message + pure-rendezvous handler.

Plugin-owned. plugin_loader registers ConIdMsg as
"direct_connect.ConIdMsg" via PROTO_MESSAGES, and handle_con_id as
the inline handler for that wire name via PROTO_HANDLERS.
"""
from typing import Any, Dict, Optional

from ....protocol.proto_msg import ProtoMsg
from aionetiface import to_n, to_s


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

    def __init__(self, data: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(data or {})


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
