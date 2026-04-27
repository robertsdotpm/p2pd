"""udp_punch protocol message + signal enum.

UdpPunchMsg subclasses tcp_punch's PunchMsg verbatim -- the payload
schema (mappings, ntp, punch_mode, nonce) is identical so all the
nat_predict / boundary_alloc machinery is reused unchanged. Only
the leading wire enum differs so the receiver routes inbound to
udp_punch instead of tcp_punch.
"""
from typing import Any, Dict, Optional

from ..tcp_punch.proto import PunchMsg


SIG_UDP_PUNCH = 10


class UdpPunchMsg(PunchMsg):
    """PunchMsg variant that wires SIG_UDP_PUNCH on the wire."""

    def __init__(self, data: Optional[Dict[str, Any]] = None, enum: int = SIG_UDP_PUNCH) -> None:
        super().__init__(data or {}, enum)
