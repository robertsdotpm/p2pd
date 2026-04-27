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

    print("[CON-ID-RX] handle_con_id plugin_id={0!r} src_tup={1!r}".format(
        plugin_id, src_tup,
    ))
    print("[CON-ID-RX]   inbound_pipes_by_tup keys: {0!r}".format(
        list(manager.inbound_pipes_by_tup.keys()),
    ))
    print("[CON-ID-RX]   inbound_pipes (futures by plugin_id) keys: {0!r}".format(
        list(manager.inbound_pipes.keys()),
    ))
    print("[CON-ID-RX]   pending_con_id_by_tup keys: {0!r}".format(
        list(manager.pending_con_id_by_tup.keys()),
    ))

    pipe = manager.inbound_pipes_by_tup.pop(src_tup, None)
    if pipe is None:
        print(
            "[CON-ID-RX]   no pipe yet at src_tup={0!r} -- registering "
            "pending claim under plugin_id={1!r}".format(src_tup, plugin_id)
        )
        manager.pending_con_id_by_tup[src_tup] = plugin_id
        return

    print("[CON-ID-RX]   matched pipe={0!r} for plugin_id={1!r}".format(
        pipe, plugin_id,
    ))
    fut = manager.inbound_pipes.get(plugin_id)
    if fut is None:
        print(
            "[CON-ID-RX]   NO future registered under plugin_id={0!r} -- "
            "reverse_connect plugin probably timed out before this signal "
            "arrived; dropping pipe match".format(plugin_id)
        )
        return
    if fut.done():
        print(
            "[CON-ID-RX]   future for plugin_id={0!r} already done(); "
            "skipping set_result".format(plugin_id)
        )
        return
    fut.set_result(pipe)
    print("[CON-ID-RX]   resolved future for plugin_id={0!r} -- "
          "reverse_connect should now wake up".format(plugin_id))
