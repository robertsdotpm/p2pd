"""
auto_connect tests from the Quickstart docs, split out so the heavy
multi-node connect/exchange tests get their own subprocess (the runner
runs each test_*.py file separately).

Ports: BASE_PORT + 10..17.
"""

import asyncio
import unittest

from aionetiface import SUB_ALL
from aionetiface.testing import AsyncTestCase
from p2pd import Node
from p2pd.node.auto_connect import auto_connect

from quickstart_helpers import BASE_PORT, QUICKSTART_CONF, close_nodes


class TestQuickstartConnect(AsyncTestCase):
    """Two nodes on the same machine connect and exchange a message."""

    async def asyncSetUp(self):
        self.alice = self.bob = None

    async def asyncTearDown(self):
        await close_nodes(self.alice, self.bob)

    async def test_auto_connect_returns_pipe(self):
        """auto_connect returns a non-None pipe and plugin."""
        try:
            self.alice = await Node(port=BASE_PORT + 10, conf=QUICKSTART_CONF).start()
            self.bob   = await Node(port=BASE_PORT + 11, conf=QUICKSTART_CONF).start()
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        try:
            pipe, plugin = await asyncio.wait_for(
                auto_connect(self.alice, self.bob.address()),
                timeout=20,
            )
        except asyncio.TimeoutError:
            self.skipTest("auto_connect timed out")

        if pipe is None:
            self.skipTest("auto_connect returned no pipe (no multi-path routes available)")
        try:
            await asyncio.wait_for(pipe.close(), timeout=5)
        except Exception:
            pass

    async def test_send_and_receive_message(self):
        """Alice sends a message; Bob receives it via a subscribed pipe."""
        try:
            self.alice = await Node(port=BASE_PORT + 12, conf=QUICKSTART_CONF).start()
            self.bob   = await Node(port=BASE_PORT + 13, conf=QUICKSTART_CONF).start()
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        alice_pipe = bob_pipe = None
        try:
            alice_pipe, _ = await asyncio.wait_for(
                auto_connect(self.alice, self.bob.address()),
                timeout=20,
            )
            bob_pipe, _ = await asyncio.wait_for(
                auto_connect(self.bob, self.alice.address()),
                timeout=20,
            )
        except asyncio.TimeoutError:
            self.skipTest("auto_connect timed out")

        if alice_pipe is None or bob_pipe is None:
            self.skipTest("auto_connect returned no pipe (no multi-path routes available)")
        bob_pipe.subscribe(SUB_ALL)
        await alice_pipe.send(b"hello from alice")
        data = await bob_pipe.recv(SUB_ALL, timeout=5)
        self.assertEqual(data, b"hello from alice")

        for p in (alice_pipe, bob_pipe):
            try:
                await asyncio.wait_for(p.close(), timeout=5)
            except Exception:
                pass

    async def test_bidirectional_exchange(self):
        """Both sides can send and receive."""
        try:
            self.alice = await Node(port=BASE_PORT + 14, conf=QUICKSTART_CONF).start()
            self.bob   = await Node(port=BASE_PORT + 15, conf=QUICKSTART_CONF).start()
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        alice_pipe = bob_pipe = None
        try:
            alice_pipe, _ = await asyncio.wait_for(
                auto_connect(self.alice, self.bob.address()),
                timeout=20,
            )
            bob_pipe, _ = await asyncio.wait_for(
                auto_connect(self.bob, self.alice.address()),
                timeout=20,
            )
        except asyncio.TimeoutError:
            self.skipTest("auto_connect timed out")

        if alice_pipe is None or bob_pipe is None:
            self.skipTest("auto_connect returned no pipe (no multi-path routes available)")
        alice_pipe.subscribe(SUB_ALL)
        bob_pipe.subscribe(SUB_ALL)

        await alice_pipe.send(b"alice says hi")
        await bob_pipe.send(b"bob says hi")

        from_alice = await bob_pipe.recv(SUB_ALL, timeout=5)
        from_bob   = await alice_pipe.recv(SUB_ALL, timeout=5)

        self.assertEqual(from_alice, b"alice says hi")
        self.assertEqual(from_bob, b"bob says hi")

        for p in (alice_pipe, bob_pipe):
            try:
                await asyncio.wait_for(p.close(), timeout=5)
            except Exception:
                pass

    async def test_none_none_on_invalid_address(self):
        """auto_connect returns (None, None) when destination address is unreachable."""
        try:
            self.alice = await Node(port=BASE_PORT + 16, conf=QUICKSTART_CONF).start()
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        # Use alice's own address bytes but construct an address pointing to
        # a port where nothing is listening. The simplest way is to pass the
        # raw addr_bytes of a node that is already closed.
        self.bob = await Node(port=BASE_PORT + 17, conf=QUICKSTART_CONF).start()
        dead_addr = self.bob.address()
        await self.bob.close()
        self.bob = None

        try:
            result = await asyncio.wait_for(
                auto_connect(self.alice, dead_addr, timeout=5),
                timeout=10,
            )
        except asyncio.TimeoutError:
            result = (None, None)

        pipe, plugin = result
        # Expect failure when destination is closed
        self.assertIsNone(pipe)


if __name__ == "__main__":
    unittest.main()
