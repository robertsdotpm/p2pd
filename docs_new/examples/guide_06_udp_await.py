"""
UDP server using async-await (queue-based recv).

P2PD lets you use the same await recv() style for UDP that you'd normally
only get with TCP stream readers.  The event loop stays free between calls.

Run:
    python3 docs/examples/guide_06_udp_await.py

Note: UDP has no delivery guarantees; a recv() timeout is normal in
lossy environments.  The example will print a timeout warning and exit
cleanly rather than raising.

Tests equivalent: tests/test_unit.py
"""

from p2pd import *


async def example():
    # Start a UDP server (no dest = server mode)
    server = await pipe_open(UDP)
    async with server:
        addr = server.sock.getsockname()[0:2]
        print("UDP server on", addr)

        # Client sends a datagram
        client = await pipe_open(UDP, addr)
        async with client:
            await client.send(b"UDP hello")

            # Await the reply on the server side
            # recv() returns None on timeout -- handle gracefully
            msg, client_tup = await server.recv(timeout=3), None
            if msg is None:
                print("No message received within timeout (normal on lossy networks).")
            else:
                print("Server got:", msg)


if __name__ == "__main__":
    async_test(example)
