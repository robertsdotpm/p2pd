"""
Detect the NAT type and WAN address for the current machine.

Queries a public STUN server using RFC 3489 mode so that the change-IP
and change-port flags are available for full NAT classification.

Run:
    python3 docs/examples/guide_03_nat_detect.py

Expected output (values vary by network):
    WAN IP      : 203.0.113.42
    Mapping     : MappingResult(ext_ip='203.0.113.42', ext_port=54321, ...)
    NAT type    : Full cone NAT  (or similar)
    Delta type  : Equal          (or similar)

Tests equivalent: tests/test_stun_client.py
"""

from p2pd import *


async def example():
    nic = await Interface()
    supported = nic.supported()
    if not supported:
        print("No supported address families found.")
        return

    af = supported[0]
    dest = ("stun.hot-chilli.net", 3478)

    client = STUNClient(af, dest, nic, proto=UDP, mode=RFC3489)

    wan_ip = await client.get_wan_ip()
    mapping = await client.get_mapping()

    print("WAN IP   :", wan_ip)
    print("Mapping  :", mapping)


if __name__ == "__main__":
    async_test(example)
