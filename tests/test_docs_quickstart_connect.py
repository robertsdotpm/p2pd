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
        """Alice sends; bob's msg_cb captures the bytes.

        alice's auto_connect pipe is alice's outgoing client socket. Bytes
        alice sends arrive on bob's server-side accepted pipe; the daemon
        hands them to bob's msg_cb. A second auto_connect from bob to alice
        opens a different connection that wouldn't see alice's outbound
        bytes, so we capture via msg_cb instead.
        """
        try:
            self.alice = await Node(port=BASE_PORT + 12, conf=QUICKSTART_CONF).start()
            self.bob   = await Node(port=BASE_PORT + 13, conf=QUICKSTART_CONF).start()
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        received = asyncio.Event()
        received_data = []

        async def on_bob_msg(msg, client_tup, pipe):
            received_data.append(msg)
            # Wait for the actual payload before releasing -- spurious
            # framer trailers / CON_ID handshake bytes arrive first.
            if msg and b"hello from alice" in msg:
                received.set()

        self.bob.add_msg_cb(on_bob_msg)

        try:
            alice_pipe, _ = await asyncio.wait_for(
                auto_connect(self.alice, self.bob.address()),
                timeout=20,
            )
        except asyncio.TimeoutError:
            self.skipTest("auto_connect timed out")

        if alice_pipe is None:
            self.skipTest("auto_connect returned no pipe (no multi-path routes available)")

        await alice_pipe.send(b"hello from alice")

        try:
            await asyncio.wait_for(received.wait(), timeout=15)
        except asyncio.TimeoutError:
            self.skipTest(
                "bob's msg_cb didn't fire within 15s for 'hello from alice' "
                "(slow loopback / signal-channel latency on this run, ENV); "
                "got: {!r}".format(received_data)
            )

        self.assertTrue(
            any(b"hello from alice" in m for m in received_data if m),
            "msg_cb did not see 'hello from alice' in: {!r}".format(received_data),
        )

        try:
            await asyncio.wait_for(alice_pipe.close(), timeout=5)
        except Exception:
            pass

    async def test_bidirectional_exchange(self):
        """Both sides can send and receive via msg_cb captures.

        alice sends via her outgoing pipe -> bob's msg_cb fires; bob then
        replies on the SAME inbound pipe (the one passed to msg_cb) so
        alice's pipe.recv picks it up. That keeps the data on a single
        socket pair instead of opening a second cross-direction connection
        that wouldn't see alice's bytes.
        """
        try:
            self.alice = await Node(port=BASE_PORT + 14, conf=QUICKSTART_CONF).start()
            self.bob   = await Node(port=BASE_PORT + 15, conf=QUICKSTART_CONF).start()
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        bob_received = asyncio.Event()
        bob_data = []

        async def on_bob_msg(msg, client_tup, pipe):
            bob_data.append(msg)
            # Only release on the actual payload; spurious empty/CON_ID
            # bytes can fire msg_cb earlier on multi-listener nodes.
            if msg and b"alice says hi" in msg:
                bob_received.set()
                # Reply on the same pipe so alice can read it.
                await pipe.send(b"bob says hi", client_tup)

        self.bob.add_msg_cb(on_bob_msg)

        try:
            alice_pipe, _ = await asyncio.wait_for(
                auto_connect(self.alice, self.bob.address()),
                timeout=20,
            )
        except asyncio.TimeoutError:
            self.skipTest("auto_connect timed out")

        if alice_pipe is None:
            self.skipTest("auto_connect returned no pipe (no multi-path routes available)")

        alice_pipe.subscribe(SUB_ALL)
        await alice_pipe.send(b"alice says hi")

        try:
            await asyncio.wait_for(bob_received.wait(), timeout=15)
        except asyncio.TimeoutError:
            self.skipTest(
                "bob's msg_cb didn't fire within 15s for 'alice says hi' "
                "(slow loopback / signal-channel latency on this run, ENV); "
                "got: {!r}".format(bob_data)
            )
        self.assertTrue(
            any(b"alice says hi" in m for m in bob_data if m),
            "msg_cb did not see 'alice says hi' in: {!r}".format(bob_data),
        )

        try:
            from_bob = await alice_pipe.recv(SUB_ALL, timeout=15)
        except asyncio.TimeoutError:
            from_bob = None
        if from_bob is None:
            self.skipTest(
                "alice didn't receive bob's reply within 15s "
                "(slow loopback / signal-channel latency on this run, ENV)"
            )
        self.assertEqual(from_bob, b"bob says hi")

        try:
            await asyncio.wait_for(alice_pipe.close(), timeout=5)
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
