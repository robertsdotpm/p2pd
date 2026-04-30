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
from typing import Any, Callable, Dict, List, Optional
from aionetiface import IP4, NIC_BIND, get_running_loop, log
from .traversal_plugin import TraversalPlugin
from .traversal_utils import (
    async_wrap_errors,
    cancel_task,
    cancel_tasks,
    close_plugin,
    h_to_b,
    log_exception,
    sig_msg_to_buf,
    to_b,
    to_s,
    try_unpack_msg,
)
from ..protocol.proto_msg import ConMsg, ProtoMsg, build_core_sig_proto


class TraversalManager:
    """Orchestrates traversal plugin lifecycle and routes signaling messages to plugins."""

    def __init__(
        self,
        router: Any,
        stop_reader: Any,
        inbound_pipes: Optional[Dict[str, Any]] = None,
        nics: Optional[List[Any]] = None,
    ) -> None:
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
        # Futures by con id -> pipe; resolved in-band by node_protocol's
        # ConId-frame peeler on the first message of each new TCP pipe.
        self.inbound_pipes = inbound_pipes if inbound_pipes is not None else {}

        # Runtime protocol-message registry. Seeded with core (plugin-
        # independent) messages; plugin_loader merges PROTO_MESSAGES
        # from each plugin's main.py into this dict at startup so the
        # central proto_msg.py never has to know about plugin-owned
        # message types.
        self.sig_proto = build_core_sig_proto()

        # Pure-rendezvous handler registry. Maps sig_enum to a callable
        # `handler(manager, msg)` that gets invoked from recv_signal_msg
        # BEFORE the plugin-creation fall-through. Used for signals that
        # carry no plugin (e.g. SIG_CON_ID, which just ties an inbound
        # pipe to an existing plugin_id future).
        self.proto_handlers = {}

        # Long-lived background tasks spawned by signal handling.
        self.tasks = []

        # Set after node_start runs.
        self.done_callback = None
        self.kp = None
        self.addr_bytes = None
        self.cleanup_task = None

    def install_plugin(self, name: str, conf: Dict[str, Any]) -> None:
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
    async def run_plugin(self, plugin: TraversalPlugin, reply: Optional[Any] = None) -> None:
        """Run a single traversal plugin, optionally providing a reply message."""
        # Don't run if result is set.
        if plugin.result.done():
            log("[TM] run_plugin skip (already done) plugin={0} id={1}".format(
                getattr(plugin, "PLUGIN_NAME", type(plugin).__name__),
                getattr(plugin, "plugin_id", "?"),
            ))
            return

        # Set nic fields.
        if reply:
            # Set an event if there's a reply.
            if not plugin.has_reply.is_set():
                plugin.has_reply.set()

            # Sets self.interface based on if_index for dest.
            reply.routing.load_if_extra(self.nics)

        log("[TM] run_plugin enter plugin={0} id={1} reply={2} timeout={3}s".format(
            getattr(plugin, "PLUGIN_NAME", type(plugin).__name__),
            getattr(plugin, "plugin_id", "?"),
            reply is not None,
            plugin.timeout,
        ))

        # Each plugin has a run method.
        try:
            await asyncio.wait_for(plugin.run(reply), timeout=plugin.timeout)
        except asyncio.CancelledError:  # pylint: disable=try-except-raise
            raise
        except (asyncio.TimeoutError, OSError, ConnectionError) as exc:
            log("[TM] run_plugin caught {0}: {1}".format(
                type(exc).__name__, repr(exc),
            ))
            log_exception()

        log("[TM] run_plugin exit plugin={0} id={1} result_done={2}".format(
            getattr(plugin, "PLUGIN_NAME", type(plugin).__name__),
            getattr(plugin, "plugin_id", "?"),
            plugin.result.done(),
        ))

        if plugin.result.done():
            await close_plugin(plugin, self.plugins, self.inbound_pipes)

    def create_plugin(
        self,
        af: Any,
        route_type: Any,
        src_info: Optional[Dict[str, Any]],
        dest_info: Optional[Dict[str, Any]],
        same_machine: bool,
        plugin_name: str,
    ) -> TraversalPlugin:
        """Instantiate and configure a traversal plugin for the given src/dest pair.

        src_info / dest_info may be None for plugins that don't pin
        a specific (src, dest) interface pair (any-pathway mode --
        used by reverse_connect when it leaves the choice up to the
        responder). The nic lookup is skipped in that case.
        """
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

        # Manager back-ref (used by fan_out to spawn / run children).
        plugin.manager = self

        # Record new plugin in dict.
        self.plugins[plugin.plugin_id] = plugin

        # Allows plugins to await on inbound cons from node server.
        plugin.set_inbound_pipes(self.inbound_pipes)

        # Load routing details in plugin. Pinned-pair plugins resolve
        # the NIC up-front; sparse plugins (any-pathway) get nic=None.
        if src_info is not None and "if_index" in src_info:
            nic = self.nics[src_info["if_index"]]
        else:
            nic = None
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

    # Use a plugin to try get a pipe to a destination node for one explicit
    # (src_info, dest_info) interface pair. Pair selection now lives at the
    # caller — auto_connect generates one (plugin, af, route_type, src_info,
    # dest_info) combo per viable pair, and node.connect picks the first
    # viable pair from get_if_infos_order. Keeping the pair out of this
    # method makes multi-interface fan-out work: launch one plugin per pair
    # and let race_plugin_results pick the winner.
    async def attempt_plugin(
        self,
        src_map: Dict[str, Any],
        dest_map: Dict[str, Any],
        sig_pipe: Any,
        plugin_name: str,
        src_info: Dict[str, Any],
        dest_info: Dict[str, Any],
        af: Any = IP4,
        route_type: Any = NIC_BIND,
    ) -> Optional[TraversalPlugin]:
        """Run the named traversal plugin for one explicit src_info/dest_info pair."""
        # Need AF supported by both.
        if not src_map[af] or not dest_map[af]:
            raise ValueError("AF not supported between hosts.")

        same_machine = dest_map["machine_id"] == src_map["machine_id"]

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
    def create_inbound_plugin(self, msg: Any) -> TraversalPlugin:
        """Create a traversal plugin for an inbound connection request, inverting src/dest."""
        # TODO: map GetAddr messages to the return_addr plugin handler.
        if isinstance(msg, ConMsg):
            msg.meta.plugin_name = "direct_connect"

        if msg.meta.plugin_name not in self.plugin_loaders:
            raise ValueError("Plugin not installed.")

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
    async def send_signal_msg(self, msg: Any, plugin: TraversalPlugin, relay_no: int = 2) -> None:
        """Encrypt and deliver a signalling message to the peer via the MQTT router."""
        print("[SIG-TX] send_signal_msg plugin_id={0!r} wire_name={1!r}".format(
            plugin.plugin_id, getattr(msg, "wire_name", "?"),
        ))
        try:
            # Specify the plugin to use in the destination.
            msg.meta = ProtoMsg.Meta.from_dict(
                {
                    # ConMsg lifetime: 120s gives generous headroom for
                    # MQTT publish jitter, broker forwarding hops, slow-VM
                    # async loop scheduling, and any slight clock drift
                    # between sender and receiver. The previous 30s budget
                    # was tight enough that fan_out's parallel-send pattern
                    # routinely raced the receiver's clock past expiry,
                    # producing the [SIG-RX] EXPIRED drops we kept seeing.
                    # 120s matches handle_publish's max_age window so the
                    # two timestamp checks share the same envelope.
                    "ttl": int(self.router.get_time()) + 120,
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
            print("[SIG-TX]   buf len={0} ttl={1} pipe_id={2!r} dest_pub={3}...".format(
                len(buf), msg.meta.ttl, plugin.plugin_id,
                plugin.dest_map["pub_key_hex"][:12],
            ))
            print("[SIG-TX]   awaiting plugin.sig_pipe.send(...)")
            await plugin.sig_pipe.send(buf)
            print("[SIG-TX]   plugin.sig_pipe.send returned (sent OK)")
        except (OSError, ConnectionError, asyncio.TimeoutError) as exc:
            print("[SIG-TX]   send_signal_msg raised: {0!r}".format(exc))
            log_exception()

    # Receive a signal message from the router and pass it to a plugin.
    # Called by the MQTT client as: handler(msg, src_pk, queue_id, client)
    async def recv_signal_msg(self, msg: Any, src_pk_hex: str, pipe_id_hex: str, client: Any) -> None:
        """Decrypt an incoming signal message and dispatch it to the matching or new plugin."""
        print("[SIG-RX] recv_signal_msg src_pk_hex={0}... pipe_id_hex={1}...".format(
            (src_pk_hex or "?")[:12], (pipe_id_hex or "?")[:12],
        ))
        msg = try_unpack_msg(to_b(msg), self.kp.private_key, self.sig_proto)
        print("[SIG-RX]   unpacked: type={0} wire_name={1!r} pipe_id={2!r} ttl={3}".format(
            type(msg).__name__,
            getattr(msg, "wire_name", "?"),
            getattr(msg.meta, "pipe_id", "?"),
            getattr(msg.meta, "ttl", "?"),
        ))

        # Message has expired.
        if int(self.router.get_time()) >= msg.meta.ttl:
            now = int(self.router.get_time())
            skew = now - msg.meta.ttl
            print("[SIG-RX]   EXPIRED ttl={0} now={1} skew={2}s; dropping".format(
                msg.meta.ttl, now, skew,
            ))
            # log() so this also lands in aionetiface logs -- when this
            # fires it's almost always a sender/receiver clock-skew bug
            # rather than a genuinely-stale message, and stdout output
            # is easy to miss across a 6-VM matrix run.
            from aionetiface import log, fstr
            log(fstr(
                "[SIG-RX] ConMsg EXPIRED: ttl={0} now={1} skew={2}s "
                "wire_name={3!r} pipe_id={4!r}; dropping. If skew is large "
                "the sender's sys_clock is probably drifted vs ours -- check "
                "NTP sync on both peers.",
                (msg.meta.ttl, now, skew,
                 getattr(msg, "wire_name", "?"),
                 getattr(msg.meta, "pipe_id", "?")),
            ))
            raise ValueError("Discarding expired msg.")

        # Update routing destination with our current address.
        msg.set_cur_addr(self.addr_bytes)

        # Pure-rendezvous handler dispatch (plugin-owned, registered via
        # PROTO_HANDLERS at load time). These signals carry no plugin --
        # they just resolve an existing future, validate inbound pipe
        # tuples, etc. -- so we handle them inline and skip the
        # plugin-creation fall-through. SIG_CON_ID is the canonical
        # example: the initiator already opened the TCP from src_tup
        # and this signal ties the accepted pipe to the plugin_id the
        # reverse_connect plugin is awaiting on.
        wire_name = getattr(msg, "wire_name", None)
        handler = self.proto_handlers.get(wire_name)
        print("[SIG-RX]   proto_handlers keys={0!r}".format(
            list(self.proto_handlers.keys()),
        ))
        if handler is not None:
            print("[SIG-RX]   dispatching to PROTO_HANDLER for {0!r}".format(wire_name))
            handler(self, msg)
            print("[SIG-RX]   PROTO_HANDLER returned for {0!r}".format(wire_name))
            return
        print("[SIG-RX]   no PROTO_HANDLER for {0!r}; plugin-creation fallthrough".format(
            wire_name,
        ))

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

    # In-band ConId rendezvous: node_protocol peels the b"P2P-CID:<id>"
    # frame off the first message on each new inbound TCP pipe and calls
    # this method to resolve the reverse_connect inbound future for the
    # plugin_id with the live pipe.
    def resolve_inbound_by_plugin_id(self, plugin_id: str, pipe: Any) -> None:
        """Resolve the reverse_connect inbound future for plugin_id with pipe."""
        fut = self.inbound_pipes.get(plugin_id)
        if fut is None:
            print("[CON-ID-RX]   no inbound future registered under plugin_id={0!r} "
                  "-- reverse_connect probably timed out before this frame "
                  "arrived; dropping pipe".format(plugin_id))
            return
        if fut.done():
            print("[CON-ID-RX]   inbound future for plugin_id={0!r} already done; "
                  "skipping set_result".format(plugin_id))
            return
        fut.set_result(pipe)
        print("[CON-ID-RX]   resolved inbound future for plugin_id={0!r} -- "
              "reverse_connect should now wake up".format(plugin_id))

    async def close(self) -> None:
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
    async def cleanup_loop(self) -> None:
        """Periodically scan for expired plugins and close them to free resources."""
        while True:
            await asyncio.sleep(5)
            try:
                now = get_running_loop().time()
                for plugin in list(self.plugins.values()):
                    if now >= plugin.expires_at:
                        await close_plugin(plugin, self.plugins, self.inbound_pipes)
            except asyncio.CancelledError:
                raise
            except (OSError, AttributeError, asyncio.TimeoutError):
                log_exception()

    def install_plugin_done_callback(self, done_callback: Callable) -> None:
        """Register a callback to be invoked when any plugin finishes."""
        self.done_callback = done_callback

    def set_send_signal_msg(self, send_signal_msg: Callable) -> None:
        """Register the function used to send signalling messages to peers."""
        self.send_signal_msg = send_signal_msg
