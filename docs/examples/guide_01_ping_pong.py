"""
Quick-start: ping-pong node.

Run two terminals.  In terminal 1:
    python3 docs/examples/guide_01_ping_pong.py server

In terminal 2:
    python3 docs/examples/guide_01_ping_pong.py client <full-name-printed-by-server>

The server will print its full nickname.  Copy it and pass it to the client.
"""

import sys
import asyncio
from p2pd import *


async def msg_cb(msg, client_tup, pipe):
    if b"PING" in msg:
        await pipe.send(b"PONG", client_tup)
        print("Received PING, sent PONG to", client_tup)


async def run_server():
    async with P2PNode() as node:
        node.add_msg_cb(msg_cb)
        full_name = await node.nickname("pingpong")
        print("Server nickname (share this):", full_name)
        print("Waiting for connections (Ctrl-C to stop)...")
        while True:
            await asyncio.sleep(1)


async def run_client(peer_name):
    async with P2PNode() as node:
        print("Connecting to", peer_name, "...")
        pipe = await node.connect(peer_name)
        async with pipe:
            await pipe.send(b"PING")
            reply = await pipe.recv()
            print("Got:", reply)
            assert reply == b"PONG"
            print("Success!")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "server"
    if mode == "server":
        async_test(run_server)
    else:
        peer = sys.argv[2]
        async_test(lambda: run_client(peer))
