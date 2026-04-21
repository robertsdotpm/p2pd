"""
Send a raw STUN binding request and print the response.

This shows the lowest-level STUN interaction: build the 20-byte header
by hand and send it over UDP.  Useful for understanding the protocol or
debugging firewall rules without any P2PD node overhead.

Run:
    python3 docs/examples/guide_04_stun_raw.py

Tests equivalent: tests/test_stun_client.py
"""

import binascii
from p2pd import *


async def example():
    # Google's public STUN server (port 19302)
    pipe = await pipe_open(UDP, ("stun.l.google.com", 19302))
    async with pipe:
        # Build a minimal STUN Binding Request (RFC 5389)
        #   type  = 0x0001  (Binding Request)
        #   len   = 0x0000  (no attributes)
        #   magic = 0x2112A442
        #   txid  = 12 random bytes
        msg_id = binascii.hexlify(rand_b(12))
        req_hex = b"0001" + b"0000" + b"2112A442" + msg_id
        req_buf = binascii.unhexlify(req_hex)

        for attempt in range(3):
            await pipe.send(req_buf)
            resp = await pipe.recv()
            if resp is not None:
                print("Raw STUN response ({} bytes):".format(len(resp)))
                print(resp.hex())
                break
            print("Attempt", attempt + 1, "timed out, retrying ...")
        else:
            print("No response after 3 attempts (check network/firewall).")


if __name__ == "__main__":
    async_test(example)
