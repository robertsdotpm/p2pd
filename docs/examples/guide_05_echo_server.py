"""
TCP echo server using the Pipe API.

Starts a TCP server that echoes every message back to the sender.
Connects a local client, sends a test message, and verifies the echo.

Demonstrates:
  - pipe_open() for servers (no dest) and clients (with dest)
  - msg_cb signature: async def cb(msg, client_tup, pipe)
  - async-with context managers for automatic cleanup

Run:
    python3 docs/examples/guide_05_echo_server.py

Tests equivalent: tests/test_unit.py  (pipe echo tests)
"""

from p2pd import *


async def echo_handler(msg, client_tup, pipe):
    print("Server received:", msg, "from", client_tup)
    await pipe.send(msg, client_tup)


async def example():
    # Start an echo server on a random port (no dest = server mode)
    server = await pipe_open(TCP, msg_cb=echo_handler)
    async with server:
        addr = server.sock.getsockname()[0:2]
        print("Echo server listening on", addr)

        # Open a TCP client pointing at the server
        client = await pipe_open(TCP, addr)
        async with client:
            msg = b"Hello, echo!"
            await client.send(msg)
            reply = await client.recv()
            print("Client received:", reply)
            assert reply == msg, "Echo mismatch: {} != {}".format(reply, msg)

    print("Done -- server and client cleaned up.")


if __name__ == "__main__":
    async_test(example)
