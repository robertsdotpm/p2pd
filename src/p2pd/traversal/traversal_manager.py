"""
Orchestrates the traversal plugin lifecycle for P2P connections.

Each connection attempt is handled by a TraversalPlugin instance. The manager
routes incoming MQTT signaling messages to the correct plugin (creating a new
one if needed), runs plugins with a timeout, and tracks background tasks.

Plugins are installed by name with a class and optional config. When a
connection is started, the manager instantiates the right plugin, loads
routing and context, and either runs it directly or dispatches a reply to a
running instance.
"""

import asyncio
from collections import OrderedDict
from aionetiface import IP4, NIC_BIND
from .traversal_utils import (
    async_wrap_errors,
    cancel_task,
    cancel_tasks,
    close_plugin,
    get_if_infos_order,
    h_to_b,
    log_exception,
    sig_msg_to_buf,
    to_b,
    to_s,
    try_unpack_msg,
)
from ..protocol.traversal.proto_msg import ConMsg, ProtoMsg, SIG_PROTO


class TraversalManager:
    """Orchestrates traversal plugin lifecycle and routes signaling messages to plugins."""

    def __init__(self, router, stop_reader, inbound_pipes=None, nics=None):
        # type: (Any, Any, Optional[Dict[str, Any]], Optional[List[Any]]) -> None
        # by plugin_id
        self.plugins = {}
        self.plugin_loaders = OrderedDict()

        # Used for signal messages.
        self.router = router

        # Socket stop signals.
        self.stop_reader = stop_reader

        # Interfaces that can be used for plugins.
        self.nics = nics if nics else []

        # Inbound connections from the node server.
        # Futures by con id -> pipe.
        self.inbound_pipes = inbound_pipes if inbound_pipes is not None else {}

        # Long-lived background tasks spawned by signal handling.
        self.tasks = []

        # Set after node_start runs.
        self.done_callback = None
        self.kp = None
        self.addr_bytes = None
        self.cleanup_task = None

    def install_plugin(self, name, conf):
        # type: (str, Dict[str, Any]) -> None
        """Register a traversal plugin class under name with the given configuration."""
        if "class" not in conf:
            raise ValueError("plugin conf must include a 'class' key")
        conf = {
            "class": conf["class"],
            "timeout": conf.get("timeout", 10),
            "cleanup": conf.get("cleanup", None),
            "set_bind": conf.get("set_bind", False),
            "max_pairs": conf.get("max_pairs", 6),
        }

        self.plugin_loaders[name] = conf

    # Plugins return pipes directly or await a pipe future that is resolved
    # elsewhere when a reply arrives over the signaling channel.
    async def run_plugin(self, plugin, reply=None):
        # type: (TraversalPlugin, Optional[Any]) -> None
        """Run a single traversal plugin, optionally providing a reply message."""
        # Don't run if result is set.
        if plugin.result.done():
            return

        # Set nic fields.
        if reply:
            # Set an event if there's a reply.
            if not plugin.has_reply.is_set():
                plugin.has_reply.set()

            # Sets self.interface based on if_index for dest.
            reply.routing.load_if_extra(self.nics)

        # Each plugin has a run method.
        try:
            await asyncio.wait_for(plugin.run(reply), timeout=plugin.timeout)
        except asyncio.CancelledError:
            raise
        except (asyncio.TimeoutError, OSError, ConnectionError):
            log_exception()

        if plugin.result.done():
            await close_plugin(plugin, self.plugins, self.inbound_pipes)

    def create_plugin(
        self, af, route_type, src_info, dest_info, same_machine, plugin_name
    ):
        # type: (Any, Any, Dict[str, Any], Dict[str, Any], bool, str) -> TraversalPlugin
        """Instantiate and configure a traversal plugin for the given src/dest pair."""
        # Meta data for this specific plugin.
        plugin_loader = self.plugin_loaders[plugin_name]

        # New instance of the plugin using init.
        plugin_class = plugin_loader["class"]
        if hasattr(plugin_class, "build_plugin"):
            plugin = plugin_class.build_plugin()
        else:
            plugin = plugin_class()

        # Socket signal for stopping cross-process.
        plugin.stop_reader = self.stop_reader

        # Record new plugin in dict.
        self.plugins[plugin.plugin_id] = plugin

        # Allows plugins to await on inbound cons from node server.
        plugin.set_inbound_pipes(self.inbound_pipes)

        # Load routing details in plugin.
        nic = self.nics[src_info["if_index"]]
        plugin.set_routing(af, src_info, dest_info, nic)

        # Load extra info about pathway.
        plugin.set_context(
            route_type,
            same_machine,
            plugin_loader["set_bind"],
            plugin_loader["timeout"],
        )

        # Used for cleaning up plugins that crash before future result ready.
        plugin.expires_at = get_running_loop().time() + plugin.timeout

        # Set function for plugin to send signaling replies.
        plugin.set_send_signal_msg(self.send_signal_msg)

        # Wire done_callback via add_done_callback so it fires whenever the
        # result resolves — even from a background task (e.g. punch process)
        # that outlives the initial run_plugin call.
        if self.done_callback:
            plugin.result.add_done_callback(self.done_callback)

        # Schedule cleanup loop if needed.
        if not self.cleanup_task or self.cleanup_task.done():
            self.cleanup_task = asyncio.create_task(self.cleanup_loop())

        return plugin

    # Use a plugin to try get a pipe to a destination node,
    async def attempt_plugin(
        self, src_map, dest_map, sig_pipe, plugin_name, af=IP4, route_type=NIC_BIND
    ):
        # type: (Dict[str, Any], Dict[str, Any], Any, str, Any, Any) -> Optional[TraversalPlugin]
        """Select interface pairs and run the named traversal plugin to reach the destination."""
        # Need AF supported by both.
        if not src_map[af] or not dest_map[af]:
            raise ValueError("AF not supported between hosts.")

        # Is this a connection to a node on the same machine?
        if dest_map["machine_id"] == src_map["machine_id"]:
            same_machine = True
        else:
            same_machine = False

        # Pairs of (src_info, dest_info) based on src / dest map.
        if_infos_order = get_if_infos_order(af, route_type, src_map, dest_map)

        # Try every interface info pair for the plugins.
        for if_infos in if_infos_order:
            src_info, dest_info = if_infos
            plugin = self.create_plugin(
                af, route_type, src_info, dest_info, same_machine, plugin_name
            )

            # Load overall addr info into the plugin.
            plugin.set_addrs(src_map, dest_map)

            # Used to communicate on MQTT.
            plugin.sig_pipe = sig_pipe

            # Run plugin function -- timeout based on plugin meta.
            await self.run_plugin(plugin)
            return plugin

    # create_plugin builds a plugin from explicit parameters — used when we are
    # the initiator and already know our src/dest addresses and route type.
    #
    # create_inbound_plugin is for the responder side: it derives those same
    # parameters from an incoming signal message, swapping src and dest so that
    # "their dest" becomes our src and "their src" becomes our dest. It also
    # reuses the pipe_id from the message so both sides share the same session.
    def create_inbound_plugin(self, msg):
        # type: (Any) -> TraversalPlugin
        """Create a traversal plugin for an inbound connection request, inverting src/dest."""
        # TODO: map GetAddr messages to the return_addr plugin handler.
        if isinstance(msg, ConMsg):
            msg.meta.plugin_name = "direct_connect"

        if msg.meta.plugin_name not in self.plugin_loaders:
            raise RuntimeError("Plugin not installed.")

        # Creates a new plugin to handle a new incoming message from router.
        plugin = self.create_plugin(
            msg.meta.af,
            msg.meta.route_type,
            src_info=msg.routing.dest_info,  # their dest = our src
            dest_info=msg.meta.src_info,  # their src = our dest
            same_machine=msg.meta.same_machine,
            plugin_name=msg.meta.plugin_name,
        )
        plugin.set_addrs(msg.routing.dest, msg.meta.src)
        plugin.set_inbound_pipes(self.inbound_pipes, msg.meta.pipe_id)
        return plugin

    # Use signal router to send a message to the destination.
    async def send_signal_msg(self, msg, plugin, relay_no=2):
        # type: (Any, TraversalPlugin, int) -> None
        """Encrypt and deliver a signalling message to the peer via the MQTT router."""
        try:
            # Specify the plugin to use in the destination.
            msg.meta = ProtoMsg.Meta.from_dict(
                {
                    "ttl": int(self.router.get_time()) + 30,
                    "pipe_id": plugin.plugin_id,
                    "af": plugin.af,
                    # Our node address with interface details.
                    "src_buf": plugin.src_map["bytes"],
                    "src_index": plugin.src_info["if_index"],
                    "route_type": plugin.route_type,
                    "same_machine": plugin.same_machine,
                    "plugin_name": msg.meta.plugin_name,
                }
            )

            # Specify details of the destination address.
            # Also includes their interface.
            msg.routing = ProtoMsg.Routing.from_dict(
                {
                    "af": plugin.af,
                    "dest_buf": plugin.dest_map["bytes"],
                    "dest_index": plugin.dest_info["if_index"],
                }
            )

            # Convert to bytes and send via MQTT.
            buf = to_s(sig_msg_to_buf(msg, h_to_b(plugin.dest_map["pub_key_hex"])))
            await plugin.sig_pipe.send(buf)
        except (OSError, ConnectionError, asyncio.TimeoutError):
            log_exception()

    # Receive a signal message from the router and pass it to a plugin.
    # Called by the MQTT client as: handler(msg, src_pk, queue_id, client)
    async def recv_signal_msg(self, msg, src_pk_hex, pipe_id_hex, client):
        # type: (Any, str, str, Any) -> None
        """Decrypt an incoming signal message and dispatch it to the matching or new plugin."""
        msg = try_unpack_msg(to_b(msg), self.kp.private_key, SIG_PROTO)

        # Message has expired.
        if int(self.router.get_time()) >= msg.meta.ttl:
            raise ValueError("Discarding expired msg.")

        # Update routing destination with our current address.
        msg.set_cur_addr(self.addr_bytes)

        # If plugin exists check sender is authorized to reach plugin.
        if msg.meta.pipe_id in self.plugins:
            plugin = self.plugins[msg.meta.pipe_id]
            if src_pk_hex != plugin.dest_map["pub_key_hex"]:
                raise ValueError("src_pk_hex mismatch for existing plugin.")

        # Plugin doesn't exist so create it.
        if msg.meta.pipe_id not in self.plugins:
            plugin = self.create_inbound_plugin(msg)

        # Route to destination via MQTT.
        if plugin.sig_pipe is None:
            plugin.sig_pipe = await self.router.pipe(
                plugin.dest_map["pub_key_hex"], use_cache=True
            )

        # Schedule the plugin run as a background task.
        # Keep a reference so the task isn't garbage-collected mid-run.
        task = asyncio.create_task(
            async_wrap_errors(self.run_plugin(plugin, reply=msg))
        )

        # Record task ref to avoid garbage collection.
        self.tasks.append(task)

        # Prune completed tasks to avoid unbounded growth.
        self.tasks = [t for t in self.tasks if not t.done()]

    async def close(self):
        # type: () -> None
        """Cancel all pending plugins and background tasks, releasing their resources."""
        await cancel_task(self.cleanup_task)
        for plugin in list(self.plugins.values()):
            try:
                await close_plugin(plugin, self.plugins, self.inbound_pipes)
            except (OSError, asyncio.TimeoutError):
                log_exception()

        await cancel_tasks(self.tasks)
        self.tasks.clear()

    # Cleanup timed out plugins.
    async def cleanup_loop(self):
        # type: () -> None
        """Periodically scan for expired plugins and close them to free resources."""
        while True:
            await asyncio.sleep(5)
            now = get_running_loop().time()
            for plugin in list(self.plugins.values()):
                if now >= plugin.expires_at:
                    await close_plugin(plugin, self.plugins, self.inbound_pipes)

    def install_plugin_done_callback(self, done_callback):
        # type: (Callable) -> None
        """Register a callback to be invoked when any plugin finishes."""
        self.done_callback = done_callback

    def set_send_signal_msg(self, send_signal_msg):
        # type: (Callable) -> None
        """Register the function used to send signalling messages to peers."""
        self.send_signal_msg = send_signal_msg
