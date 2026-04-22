"""
Demonstrate each connection strategy individually.

Usage (two terminals):

    Terminal 1 (server):
        python3 docs/examples/guide_02_strategies.py server

    Terminal 2 (client) -- replace <name> with nickname printed by server:
        python3 docs/examples/guide_02_strategies.py direct  <name>
        python3 docs/examples/guide_02_strategies.py reverse <name>
        python3 docs/examples/guide_02_strategies.py punch   <name>
        python3 docs/examples/guide_02_strategies.py all     <name>

Strategy notes:
  direct  -- works when the server is directly reachable (data-centre / UPnP).
  reverse -- the server connects back to you via MQTT signaling.
  punch   -- both sides send SYN packets simultaneously (requires NTP sync).
  all     -- tries direct → reverse → punch in order, returns first success.
"""

import sys
import asyncio
from p2pd import *

STRATEGY_MAP = {
    "direct": [P2P_DIRECT],
    "reverse": [P2P_REVERSE],
    "punch": [P2P_PUNCH],
    "all": [P2P_DIRECT, P2P_REVERSE, P2P_PUNCH],
}


async def echo_cb(msg, client_tup, pipe):
    await pipe.send(msg, client_tup)


async def run_server():
    async with P2PNode() as node:
        node.add_msg_cb(echo_cb)
        full_name = await node.nickname("strategies")
        print("Server nickname:", full_name)
        print("Listening ... (Ctrl-C to stop)")
        while True:
            await asyncio.sleep(1)


async def run_client(strategy_key, peer_name):
    strategies = STRATEGY_MAP[strategy_key]
    print("Connecting via strategy:", strategy_key)
    async with P2PNode() as node:
        pipe = await node.connect(peer_name, strategies=strategies)
        async with pipe:
            await pipe.send(b"Hello via " + strategy_key.encode())
            reply = await pipe.recv()
            print("Echo:", reply)


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == "server":
        async_test(run_server)
    else:
        strategy = sys.argv[1]
        peer = sys.argv[2]
        async_test(lambda: run_client(strategy, peer))
