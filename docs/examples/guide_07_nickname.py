"""
Register a nickname and print the full name to share with peers.

P2PD's naming system (PNP -- Peer Name Protocol) lets you register a
short, memorable name.  After registration a TLD is appended so the
returned name is globally unique and resolvable.

Run:
    python3 docs/examples/guide_07_nickname.py

The full name printed (e.g. "mynode.peer") is what you give to other
nodes when they call node.connect().

Tests equivalent: tests/test_p2p_addr.py
"""

from p2pd import *


async def example():
    async with P2PNode() as node:
        # Print raw address bytes before registering a name
        print("Raw address:", node.addr_bytes.decode())

        # Register nickname -- returns the full name with TLD appended
        full_name = await node.nickname("mynode")
        print("Share this name:", full_name)

        # Another node can connect with:
        #   pipe = await other_node.connect(full_name)
        print("Example connect call:")
        print('  pipe = await other_node.connect("{}")'.format(full_name))


if __name__ == "__main__":
    async_test(example)
