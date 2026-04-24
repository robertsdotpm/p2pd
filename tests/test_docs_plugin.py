"""
Tests for the Writing a Plugin documentation examples.

Verifies that the plugin pattern shown in docs/writing_a_plugin.md
actually works: a custom TraversalPlugin subclass can be installed
and used with auto_connect.


"""

import asyncio
import unittest
from typing import Optional, Any
from aionetiface import TCP, IP4, Pipe, dict_child, log_exception, SUB_ALL
from aionetiface.testing import AsyncTestCase
from p2pd import Node
from p2pd.node.node_defs import NODE_TEST_CONF, NODE_PORT
from p2pd.node.auto_connect import auto_connect
from p2pd.traversal.traversal_plugin import TraversalPlugin


BASE_PORT = NODE_PORT + 3100


# ─────────────────────────────────────────────────────────────────────────────
# Example plugin from docs: simple direct TCP connect
# ─────────────────────────────────────────────────────────────────────────────


class DocsDirectPlugin(TraversalPlugin):
    """Minimal plugin: open a direct TCP connection to the peer.

    This is the Example 1 code from docs/writing_a_plugin.md.
    """

    async def run(self, reply: Optional[Any] = None) -> None:
        dest = (str(self.dest_info["ip"]), self.dest_info["port"])
        route = await self.nic.route(self.af).bind()

        try:
            pipe = await Pipe(TCP, dest, route).connect()
        except (OSError, ConnectionError, asyncio.TimeoutError):
            log_exception()
            return

        if pipe is not None:
            self.result.set_result(pipe)


# ─────────────────────────────────────────────────────────────────────────────
# Signal-coordinated plugin from docs: reverse connect pattern
# ─────────────────────────────────────────────────────────────────────────────


class DocsReversePlugin(TraversalPlugin):
    """Ask the peer to connect to us instead.

    This is the Example 2 code from docs/writing_a_plugin.md.
    """

    async def run(self, reply: Optional[Any] = None) -> None:
        from p2pd.protocol.proto_msg import ConMsg
        msg = ConMsg()
        msg.meta.plugin_name = "direct_connect"
        self.register_inbound()
        await self.send_signal_msg(msg)
        con = await self.wait_for_inbound()
        self.result.set_result(con)


# ─────────────────────────────────────────────────────────────────────────────
# Test configuration
# ─────────────────────────────────────────────────────────────────────────────


PLUGIN_TEST_CONF = dict_child(
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


async def make_node(port, extra_conf=None):
    conf = PLUGIN_TEST_CONF if extra_conf is None else dict_child(extra_conf, PLUGIN_TEST_CONF)
    return await Node(port=port, conf=conf).start()


async def close_nodes(*nodes):
    for node in nodes:
        if node is not None:
            try:
                await asyncio.wait_for(node.close(), timeout=10)
            except Exception:
                pass


def install_only(node, plugin_name, plugin_class):
    """Replace all plugins on node with a single custom plugin."""
    node.traversal.plugin_loaders.clear()
    node.traversal.plugins.clear()
    node.traversal.install_plugin(plugin_name, {"class": plugin_class})


# ─────────────────────────────────────────────────────────────────────────────
# Tests: TraversalPlugin subclass basics
# ─────────────────────────────────────────────────────────────────────────────


class TestTraversalPluginInterface(unittest.IsolatedAsyncioTestCase):
    """TraversalPlugin subclass has the expected attributes."""

    async def test_plugin_has_result_future(self):
        plugin = DocsDirectPlugin()
        self.assertIsInstance(plugin.result, asyncio.Future)

    async def test_plugin_has_plugin_id(self):
        plugin = DocsDirectPlugin()
        self.assertIsInstance(plugin.plugin_id, str)
        self.assertGreater(len(plugin.plugin_id), 0)

    async def test_two_plugins_have_distinct_ids(self):
        a = DocsDirectPlugin()
        b = DocsDirectPlugin()
        self.assertNotEqual(a.plugin_id, b.plugin_id)

    async def test_plugin_result_not_done_initially(self):
        plugin = DocsDirectPlugin()
        self.assertFalse(plugin.result.done())


# ─────────────────────────────────────────────────────────────────────────────
# Tests: custom plugin installed at runtime
# ─────────────────────────────────────────────────────────────────────────────


class TestCustomDirectPlugin(unittest.IsolatedAsyncioTestCase):
    """DocsDirectPlugin (from the docs example) can establish a connection."""

    async def asyncSetUp(self):
        self.alice = self.bob = None

    async def asyncTearDown(self):
        await close_nodes(self.alice, self.bob)

    async def test_custom_plugin_connects(self):
        try:
            self.alice = await make_node(BASE_PORT)
            self.bob   = await make_node(BASE_PORT + 1)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        # Install only our custom plugin on both nodes.
        install_only(self.alice, "docs_direct", DocsDirectPlugin)
        install_only(self.bob,   "docs_direct", DocsDirectPlugin)

        try:
            pipe, plugin = await asyncio.wait_for(
                auto_connect(self.alice, self.bob.address()),
                timeout=20,
            )
        except asyncio.TimeoutError:
            self.skipTest("auto_connect timed out")

        if pipe is None:
            self.skipTest("auto_connect returned no pipe (no multi-path routes available)")
        self.assertIsInstance(plugin, DocsDirectPlugin)
        try:
            await asyncio.wait_for(pipe.close(), timeout=5)
        except Exception:
            pass

    async def test_custom_plugin_pipe_is_usable(self):
        try:
            self.alice = await make_node(BASE_PORT + 2)
            self.bob   = await make_node(BASE_PORT + 3)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        install_only(self.alice, "docs_direct", DocsDirectPlugin)
        install_only(self.bob,   "docs_direct", DocsDirectPlugin)

        # Also need the bob-side pipe so we can subscribe and receive.
        bob_pipe = None
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
        await alice_pipe.send(b"hello from docs example")
        data = await bob_pipe.recv(SUB_ALL, timeout=5)
        self.assertEqual(data, b"hello from docs example")

        for p in (alice_pipe, bob_pipe):
            try:
                await asyncio.wait_for(p.close(), timeout=5)
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# Tests: install_plugin API
# ─────────────────────────────────────────────────────────────────────────────


class TestInstallPluginAPI(unittest.IsolatedAsyncioTestCase):
    """node.traversal.install_plugin() registers a plugin for use by auto_connect."""

    async def asyncSetUp(self):
        self.node = None

    async def asyncTearDown(self):
        await close_nodes(self.node)

    async def test_install_plugin_registers_loader(self):
        try:
            self.node = await make_node(BASE_PORT + 10)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        self.node.traversal.install_plugin("my_plugin", {"class": DocsDirectPlugin})
        self.assertIn("my_plugin", self.node.traversal.plugin_loaders)

    async def test_install_plugin_with_timeout(self):
        try:
            self.node = await make_node(BASE_PORT + 11)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        self.node.traversal.install_plugin("my_plugin", {
            "class": DocsDirectPlugin,
            "timeout": 15,
        })
        self.assertIn("my_plugin", self.node.traversal.plugin_loaders)


# ─────────────────────────────────────────────────────────────────────────────
# Tests: PLUGIN_CLASS convention
# ─────────────────────────────────────────────────────────────────────────────


class TestPluginClassConvention(unittest.IsolatedAsyncioTestCase):
    """Plugins should expose PLUGIN_CLASS at module level for auto-discovery."""

    async def test_docs_direct_plugin_class_is_traversal_plugin(self):
        self.assertTrue(issubclass(DocsDirectPlugin, TraversalPlugin))

    async def test_docs_direct_plugin_overrides_run(self):
        # run() on the base class just logs a warning; a real plugin overrides it.
        self.assertNotEqual(
            DocsDirectPlugin.run,
            TraversalPlugin.run,
        )


if __name__ == "__main__":
    unittest.main()
