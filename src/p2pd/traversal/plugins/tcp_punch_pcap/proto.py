"""Wire-level message for the pcap-based punch plugin.

PunchPcapMsg is the same shape as PunchMsg (and inherits all of its
serialization helpers via the ProtoMsg base) but is registered under a
distinct wire name so plugin_loader can route inbound signals to the
pcap plugin specifically.  This keeps the legacy tcp_punch plugin
oblivious to our existence -- it never sees PunchPcapMsg in its
dispatch table.

Why subclass instead of reusing PunchMsg directly: plugin_loader
derives wire names as "<plugin_name>.<MsgClass.__name__>".  If we
listed (PunchMsg, ...) in PunchPcapPlugin.proto_messages we would
re-register the SAME class under a second wire name -- and proto_msg
matching at the receiver would have to disambiguate by hand.  A
subclass keeps the name (and therefore the registry key) unique.
"""

from ..tcp_punch.proto import PunchMsg


class PunchPcapMsg(PunchMsg):
    """Wire message identical to PunchMsg.

    Payload class is inherited from PunchMsg unchanged; the only thing
    that differs is the WIRE_NAME attribute, which plugin_loader
    patches on import as "tcp_punch_pcap.PunchPcapMsg".
    """

    # Reuse PunchMsg.Payload directly via inheritance -- no overrides
    # needed.  Receiver side will reconstruct via PunchMsg.Payload.from_dict.
