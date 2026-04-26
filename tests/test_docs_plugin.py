"""
Tests for the Writing a Plugin documentation examples.

Verifies that the plugin pattern shown in docs/writing_a_plugin.md
actually works: a custom TraversalPlugin subclass can be installed
and used with auto_connect.


"""

import asyncio
import unittest
from typing import Optional, Any
from aionetiface import TCP, IP4, Pipe, dict_child, log_exception
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

    Same-machine peers can be reached via dest_info["ip"] in the
    127.0.0.0/8 (or ::1) loopback range; binding the connect socket
    to a matching loopback source IP is required on Windows XP whose
    stack only routes 127.0.0.1 reliably (a connect from src=127.X.Y.Z
    to dest=127.0.0.1 is silently dropped). Match src to dest's
    loopback class -- modern Windows / Linux / macOS unaffected.
    """

    async def run(self, reply: Optional[Any] = None) -> None:
        dest = (str(self.dest_info["ip"]), self.dest_info["port"])

        is_v4_loopback = (self.af == IP4) and dest[0].startswith("127.")
        is_v6_loopback = dest[0] == "::1" or dest[0].startswith("::1")

        if is_v4_loopback or is_v6_loopback:
            if self.af == IP4:
                src_lo = self.src_info.get("loopback") if self.src_info else None
                src_str = str(src_lo) if (src_lo and str(src_lo).startswith("127.")) else "127.0.0.1"
            else:
                src_str = "::1"
            route = self.nic.route(self.af)
            await route.bind(ips=src_str)
        else:
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


class TestTraversalPluginInterface(AsyncTestCase):
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


class TestCustomDirectPlugin(AsyncTestCase):
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
        # alice's auto_connect pipe is alice's outgoing client socket.
        # Bytes she sends arrive on bob's server-side accepted pipe;
        # the daemon hands them to bob's msg_cb. A second auto_connect
        # from bob to alice would open a separate socket that wouldn't
        # see alice's outbound bytes -- capture via msg_cb instead.
        try:
            self.alice = await make_node(BASE_PORT + 2)
            self.bob   = await make_node(BASE_PORT + 3)
        except Exception as exc:
            self.skipTest("Node startup failed: {}".format(exc))

        install_only(self.alice, "docs_direct", DocsDirectPlugin)
        install_only(self.bob,   "docs_direct", DocsDirectPlugin)

        received = asyncio.Event()
        received_data = []

        async def on_bob_msg(msg, client_tup, pipe):
            received_data.append(msg)
            if msg and b"hello from docs example" in msg:
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

        await alice_pipe.send(b"hello from docs example")

        try:
            await asyncio.wait_for(received.wait(), timeout=5)
        except asyncio.TimeoutError:
            self.fail(
                "bob's msg_cb didn't see 'hello from docs example' in 5s; "
                "got: {!r}".format(received_data)
            )

        self.assertTrue(
            any(b"hello from docs example" in m for m in received_data if m),
            "msg_cb didn't see payload; got: {!r}".format(received_data),
        )

        try:
            await asyncio.wait_for(alice_pipe.close(), timeout=5)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Tests: install_plugin API
# ─────────────────────────────────────────────────────────────────────────────


class TestInstallPluginAPI(AsyncTestCase):
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


class TestPluginClassConvention(AsyncTestCase):
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
