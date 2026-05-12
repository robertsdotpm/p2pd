"""udp_punch protocol message.

UdpPunchMsg subclasses tcp_punch's PunchMsg verbatim -- the payload
schema (mappings, ntp, punch_mode, nonce) is identical so all the
nat_predict / boundary_alloc machinery is reused unchanged. Only
the wire name differs so the receiver routes inbound to udp_punch
instead of tcp_punch. plugin_loader patches WIRE_NAME to
"udp_punch.UdpPunchMsg" at install time.
"""

from ..tcp_punch.proto import PunchMsg


class UdpPunchMsg(PunchMsg):
    """PunchMsg variant routed to udp_punch by its qualified wire name."""

    def __init__(self, data=None):
        super().__init__(data or {})
