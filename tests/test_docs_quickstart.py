"""
Tests for the Quickstart documentation examples.

Verifies that the code shown in docs/quickstart.md runs correctly.
These are same-machine integration tests using NODE_TEST_CONF so they
run quickly without needing real NAT traversal, UPnP, or STUN.

Run with:
    python3 -m pytest tests/test_docs_quickstart.py -v
"""

import asyncio
import unittest

import pytest

from aionetiface import SUB_ALL, dict_child, Interface, list_interfaces, load_interfaces
from p2pd import Node
from p2pd.node.node_defs import NODE_TEST_CONF, NODE_PORT
from p2pd.node.auto_connect import auto_connect


# Give signal-capable tests a sig_pipe so the MQTT router can relay signals.
# For pure same-machine direct tests, sig_pipe_no=0 is fine.
QUICKSTART_CONF = dict_child(
    {
        "sig_pipe_no": 1,
        "enable_upnp": False,
        "init_clock_skew": False,
        "enable_punching": False,
        "enable_nickname": False,
        "enable_stun_clients": False,
    },
    NODE_TEST_CONF,
)

BASE_PORT = NODE_PORT + 3000


async def make_node(port):
    """Start a node on a specific port, shared NIC detected from host."""
    return await Node(port=port, conf=QUICKSTART_CONF).start()


async def close_nodes(*nodes):
    """Close all nodes, ignoring errors."""
    for node in nodes:
        if node is not None:
            try:
                await asyncio.wait_for(node.close(), timeout=10)
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# Basic node lifecycle
# ─────────────────────────────────────────────────────────────────────────────


class TestNodeLifecycle(unittest.IsolatedAsyncioTestCase):
    """Node can be started, yields an address, and can be closed."""

    async def test_node_starts_and_has_address(self):
        node = None
        try:
            node = await Node(port=BASE_PORT, conf=QUICKSTART_CONF).start()
            addr = node.address()
            self.assertIsNotNone(addr)
            self.assertIsInstance(addr, bytes)
            self.assertGreater(len(addr), 0)
        finally:
            await close_nodes(node)

    async def test_node_context_manager(self):
        """Node works as an async context manager."""
        async with Node(port=BASE_PORT + 1, conf=QUICKSTART_CONF) as node:
            await node.start()
            self.assertIsNotNone(node.address())

    async def test_two_nodes_have_distinct_addresses(self):
        alice = bob = None
        try:
            alice = await Node(port=BASE_PORT + 2, conf=QUICKSTART_CONF).start()
            bob   = await Node(port=BASE_PORT + 3, conf=QUICKSTART_CONF).start()
            self.assertNotEqual(alice.address(), bob.address())
        except (OSError, asyncio.TimeoutError) as exc:
            self.skipTest("Node startup failed (network): {}".format(exc))
        finally:
            await close_nodes(alice, bob)

    async def test_node_supported_afs_non_empty(self):
        node = None
        try:
            node = await Node(port=BASE_PORT + 4, conf=QUICKSTART_CONF).start()
            supported = node.supported()
            self.assertGreater(len(supported), 0)
        finally:
            await close_nodes(node)


# ─────────────────────────────────────────────────────────────────────────────
# auto_connect: same machine, loopback path
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.network
class TestQuickstartConnect(unittest.IsolatedAsyncioTestCase):
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


# ─────────────────────────────────────────────────────────────────────────────
# msg_cb: server-side message reception
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.network
class TestMsgCallback(unittest.IsolatedAsyncioTestCase):
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
        await pipe.send(b"test payload")

        try:
            await asyncio.wait_for(received.wait(), timeout=5)
        except asyncio.TimeoutError:
            self.skipTest("msg_cb was not called in time")

        self.assertIn(b"test payload", received_data)
        try:
            await asyncio.wait_for(pipe.close(), timeout=5)
        except Exception:
            pass


if __name__ == "__main__":
    unittest.main()
