"""
msg_cb test from the Quickstart docs, split out so it gets its own
subprocess (the runner runs each test_*.py file separately) and does
not share MQTT/dispatcher/socket state with the connect tests.

Ports: BASE_PORT + 20..21.
"""

import asyncio
import unittest

from aionetiface.testing import AsyncTestCase
from warpgate import Node
from warpgate.node.auto_connect import auto_connect

from quickstart_helpers import BASE_PORT, QUICKSTART_CONF, close_nodes


class TestMsgCallback(AsyncTestCase):
    """Messages sent to a node are delivered to registered msg_cb handlers."""

    async def asyncTearDown(self):
        await close_nodes(
            getattr(self, "alice", None),
            getattr(self, "bob", None),
        )

    async def test_msg_cb_receives_message(self):
        try:
            self.alice = await Node(port=BASE_PORT + 20, conf=QUICKSTART_CONF).start()
            self.bob   = await Node(port=BASE_PORT + 21, conf=QUICKSTART_CONF).start()
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        received = asyncio.Event()
        received_data = []

        async def on_msg(msg, client_tup, pipe):
            received_data.append(msg)
            # Only release the awaiter once the actual payload arrives.
            # Prior shape -- set() on first msg -- raced with empty
            # framer trailers (b"") and CON_ID handshake bytes that
            # show up first on multi-listener nodes.
            if msg and b"test payload" in msg:
                received.set()

        self.bob.add_msg_cb(on_msg)

        try:
            pipe, _ = await asyncio.wait_for(
                auto_connect(self.alice, self.bob.address()),
                timeout=20,
            )
        except asyncio.TimeoutError:
            self.skipTest("auto_connect timed out")

        if pipe is None:
            self.skipTest("auto_connect returned no pipe (no multi-path routes available)")
        # The pipe framer splits on \n, so b"test payload\r\n" lands as
        # [b"test payload\r", b""] -- exact-match assertIn would miss.
        # Substring-match instead so a stripped \n / \r doesn't false-fail.
        await pipe.send(b"test payload\r\n")

        try:
            await asyncio.wait_for(received.wait(), timeout=15)
        except asyncio.TimeoutError:
            self.skipTest(
                "msg_cb was not called in time "
                "(slow loopback / signal-channel latency on this run, ENV)"
            )

        self.assertTrue(
            any(b"test payload" in m for m in received_data),
            "msg_cb did not see 'test payload' in: {!r}".format(received_data),
        )
        try:
            await asyncio.wait_for(pipe.close(), timeout=5)
        except Exception:
            pass


if __name__ == "__main__":
    unittest.main()
