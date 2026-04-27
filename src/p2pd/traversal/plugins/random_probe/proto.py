"""random_probe protocol message.

Plugin-owned. plugin_loader registers RandomProbeMsg under wire
name "random_probe.RandomProbeMsg" via PROTO_MESSAGES.
"""
from typing import Any, Dict

from ....protocol.proto_msg import ProtoMsg


class RandomProbeMsg(ProtoMsg):
    """Carries random-probe rendezvous parameters for symmetric NAT traversal.

    Both sides exchange one of these.  The cone (endpoint-independent)
    side advertises its known external (ip, port).  The symmetric side
    advertises only its external IP -- its outbound port mappings are
    random per-flow and have to be discovered via the probe collision.

    role: "sym" if my own NAT is symmetric, "non_sym" otherwise
          (covers open internet, full cone, restricted, port-
          restricted -- the algorithm only really cares whether
          my outbound port is predictable per flow).
    """

    class Payload:
        """Random-probe payload: rendezvous time, both ext IPs, cone known port, magic."""

        def __init__(
            self,
            role: str,
            punch_time: int,
            magic: str,
            ext_ip: str,
            known_port: int = 0,
            probe_count: int = 256,
        ) -> None:
            self.role = role
            self.punch_time = int(punch_time)
            self.magic = magic
            self.ext_ip = ext_ip
            self.known_port = int(known_port)
            self.probe_count = int(probe_count)

        def to_dict(self) -> Dict[str, Any]:
            return {
                "role": self.role,
                "punch_time": self.punch_time,
                "magic": self.magic,
                "ext_ip": self.ext_ip,
                "known_port": self.known_port,
                "probe_count": self.probe_count,
            }

        @staticmethod
        def from_dict(d: Dict[str, Any]) -> "RandomProbeMsg.Payload":
            return RandomProbeMsg.Payload(
                d.get("role", "non_sym"),
                d.get("punch_time", 0),
                d.get("magic", ""),
                d.get("ext_ip", ""),
                d.get("known_port", 0),
                d.get("probe_count", 256),
            )

    def __init__(self, data: Dict[str, Any]) -> None:
        super().__init__(data)
