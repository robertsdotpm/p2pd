"""
Orchestrates the traversal plugin lifecycle for P2P connections.

Each connection attempt is handled by a Plugin instance. The manager
routes incoming MQTT signaling messages to the correct plugin (creating a new
one if needed), runs plugins with a timeout, and tracks background tasks.

Plugins are installed by name with a class and optional config. When a
connection is started, the manager instantiates the right plugin, loads
routing and context, and either runs it directly or dispatches a reply to a
running instance.
"""

import asyncio
from collections import OrderedDict
from aionetiface import IP4, NIC_BIND, get_running_loop, log
from .traversal_plugin import Plugin
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
        router,
        stop_reader,
        inbound_pipes=None,
        nics=None,
        node_msg_cb=None,
    ):
        # by plugin_id
        self.plugins = {}
        self.plugin_loaders = OrderedDict()

        # Used for signal messages.
        self.router = router

        # Socket stop signals.
        self.stop_reader = stop_reader

        # Node-level message dispatcher. Plugins (and any pipes they
        # spawn internally, e.g. tcp_punch's reverse_server) need it
        # to pre-populate msg_cbs BEFORE the first inbound byte
        # arrives -- the on_plugin_done path attaches it AFTER
        # set_result, which races a fast-arriving ECHO and drops
        # data on the "No msg cbs registered" path.
        self.node_msg_cb = node_msg_cb

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

        # Cached OS-default-route Interface used for loopback binds
        # (binding 127.x on a real NIC raises EINVAL + the
        # SO_BINDTODEVICE pin would block lo delivery).  Built lazily
        # on first use; reused for every subsequent loopback combo.
        self.default_nic_cache = None

    def default_nic(self):
        """Return the cached Interface("default") used for loopback binds."""
        if self.default_nic_cache is None:
            from aionetiface import Interface
            if Interface.default is None:
                Interface.default = Interface("default")
            self.default_nic_cache = Interface.default
        return self.default_nic_cache

    def install_plugin(self, name, conf):
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
        """Run a single traversal plugin, optionally providing a reply message."""
        # Don't run if result is set.
        if plugin.result.done():
            log("[TM] run_plugin skip (already done) plugin={0} id={1}".format(
                getattr(plugin, "name", type(plugin).__name__),
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
            getattr(plugin, "name", type(plugin).__name__),
            getattr(plugin, "plugin_id", "?"),
            reply is not None,
            plugin.timeout,
        ))

        # Each plugin has a run method.  Plugins that return from run()
        # normally may have spawned a background task (e.g. tcp_punch's
        # punch process) that resolves plugin.result later; do NOT
        # touch result on the normal-return path or we'd race that
        # task and prematurely fail a successful punch.  But on every
        # ERROR path -- caught, timeout, or uncaught -- run() will not
        # produce a result; resolve plugin.result to None so callers
        # awaiting it (demo, race_plugin_results) return immediately.
        try:
            await asyncio.wait_for(plugin.run(reply), timeout=plugin.timeout)
        except asyncio.CancelledError:
            if not plugin.result.done():
                plugin.result.cancel()
            asyncio.ensure_future(async_wrap_errors(close_plugin(plugin, self.plugins, self.inbound_pipes)))
            raise
        except (asyncio.TimeoutError, OSError, ConnectionError) as exc:
            log("[TM] run_plugin caught {0}: {1}".format(
                type(exc).__name__, repr(exc),
            ))
            log_exception()
            if not plugin.result.done():
                plugin.result.set_result(None)
        except Exception:  # pylint: disable=broad-except
            log_exception()
            if not plugin.result.done():
                plugin.result.set_result(None)
            raise

        log("[TM] run_plugin exit plugin={0} id={1} result_done={2}".format(
            getattr(plugin, "name", type(plugin).__name__),
            getattr(plugin, "plugin_id", "?"),
            plugin.result.done(),
        ))

        if plugin.result.done():
            result_val = None
            try:
                result_val = plugin.result.result()
            except (asyncio.CancelledError, Exception):
                pass
            if result_val is not None:
                plugin.expires_at = get_running_loop().time() + 3600
                log("[TM] run_plugin success: extended expires_at by 3600s for plugin={0}".format(
                    getattr(plugin, "plugin_id", "?"),
                ))
            else:
                await close_plugin(plugin, self.plugins, self.inbound_pipes)

    def create_plugin(
        self,
        af,
        route_type,
        src,
        dest,
        same_machine,
        plugin_name,
    ):
        """Instantiate and configure a traversal plugin for the given src/dest pair.

        src / dest may be None for plugins that don't pin
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

        # Node-level msg dispatcher; plugins propagate it into any
        # pipes they create internally so msg_cbs is non-empty before
        # the first inbound byte arrives.
        plugin.node_msg_cb = self.node_msg_cb

        # Manager back-ref (used by fan_out to spawn / run children).
        plugin.manager = self

        # Record new plugin in dict.
        self.plugins[plugin.plugin_id] = plugin

        # Allows plugins to await on inbound cons from node server.
        plugin.set_inbound_pipes(self.inbound_pipes)

        # Load routing details in plugin. Pinned-pair plugins resolve
        # the NIC up-front; sparse plugins (any-pathway) get nic=None.
        if src is not None and "if_index" in src:
            nic = self.nics[src["if_index"]]
        else:
            nic = None

        # Pre-resolve (ip, port) per route_type before the plugin sees
        # the per-side dicts.  Plugins read self.src["ip"] /
        # ["port"] and self.dest["ip"] / ["port"] directly -- no
        # route_type / fe80 / loopback-candidate branching inside
        # plugin code.  See traversal_utils.resolve_pair.
        if src is not None and dest is not None and route_type is not None:
            from .traversal_utils import resolve_pair
            src, dest = resolve_pair(
                af, route_type, src, dest, nic, same_machine,
            )

            # Pick the right Interface for binding.  Loopback IPs (per-
            # pubkey 127.X.Y.Z, 127.0.0.1, ::1) need Interface("default"):
            # binding 127.x on a NIC route raises EINVAL because the IP
            # doesn't live on that interface, AND the apply_nic_pin_sockopts
            # SO_BINDTODEVICE pin would tie the socket to a physical NIC
            # so the kernel's lo router can't deliver SYNs.  Interface("default")
            # has name="default", which the SO_BINDTODEVICE call rejects with
            # ENODEV, leaving the socket cleanly unpinned.
            #
            # Plugins read this nic via self.nic.route(af) without caring
            # whether they got the physical NIC or the default placeholder.
            ip_str = (src.get("ip") or "")
            is_loopback = ip_str.startswith("127.") or ip_str.startswith("::1") or ip_str == "::1"
            if is_loopback:
                nic = self.default_nic()

        plugin.set_routing(af, src, dest, nic)

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
        plugin.set_send_signal(self.send_signal)

        # Wire done_callback via add_done_callback so it fires whenever the
        # result resolves — even from a background task (e.g. punch process)
        # that outlives the initial run_plugin call.
        if self.done_callback:
            plugin.result.add_done_callback(self.done_callback)

        # Schedule cleanup loop if needed.
        if not self.cleanup_task or self.cleanup_task.done():
            self.cleanup_task = get_running_loop().create_task(self.cleanup_loop())

        return plugin

    # Use a plugin to try get a pipe to a destination node for one explicit
    # (src, dest) interface pair. Pair selection now lives at the
    # caller — auto_connect generates one (plugin, af, route_type, src,
    # dest) combo per viable pair, and node.connect picks the first
    # viable pair from get_if_infos_order. Keeping the pair out of this
    # method makes multi-interface fan-out work: launch one plugin per pair
    # and let race_plugin_results pick the winner.
    async def attempt_plugin(
        self,
        src_map,
        dest_map,
        sig_pipe,
        plugin_name,
        src,
        dest,
        af=IP4,
        route_type=NIC_BIND,
    ):
        """Run the named traversal plugin for one explicit src/dest pair."""
        # Need AF supported by both.
        if not src_map[af] or not dest_map[af]:
            raise ValueError("AF not supported between hosts.")

        same_machine = dest_map["machine_id"] == src_map["machine_id"]
        log("[TM] attempt_plugin: plugin={0} af={1} route_type={2} "
            "same_machine={3} (src_mid={4} dest_mid={5})".format(
                plugin_name, af, route_type, same_machine,
                str(src_map.get("machine_id"))[:10],
                str(dest_map.get("machine_id"))[:10],
            ))

        plugin = self.create_plugin(
            af, route_type, src, dest, same_machine, plugin_name
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
        """Create a traversal plugin for an inbound connection request, inverting src/dest."""
        # TODO: map GetAddr messages to the return_addr plugin handler.
        if isinstance(msg, ConMsg):
            msg.meta.plugin_name = "direct_connect"

        # Asymmetric tcp_punch -> tcp_punch_pcap override:
        # When the peer sends a PunchMsg labelled plugin_name="tcp_punch"
        # but OUR local OS is NT-5 (XP / 2000) AND we have the
        # tcp_punch_pcap plugin installed, redirect locally to
        # tcp_punch_pcap.  The peer can't know our OS at signal-
        # dispatch time (they pick their plugin from THEIR OS), so
        # the redirection must happen here, on the receiver side.
        # The wire bytes are identical (both plugins share
        # tcp_punch.PunchMsg) -- only the local plugin instantiated
        # to handle the message changes.
        # See warpgate/src/warpgate/traversal/plugins/tcp_punch_pcap/__init__.py
        # for the full design rationale.
        if (
            msg.meta.plugin_name == "tcp_punch"
            and "tcp_punch_pcap" in self.plugin_loaders
        ):
            try:
                from aionetiface import os_id
                local_os = os_id() or ""
            except ImportError:
                local_os = ""
            if (
                local_os.startswith("Windows-XP")
                or local_os.startswith("Windows-2000")
            ):
                log("create_inbound_plugin: redirecting tcp_punch -> "
                    "tcp_punch_pcap (local OS {0!r})".format(local_os))
                msg.meta.plugin_name = "tcp_punch_pcap"

        if msg.meta.plugin_name not in self.plugin_loaders:
            raise ValueError("Plugin not installed.")

        # Creates a new plugin to handle a new incoming message from router.
        plugin = self.create_plugin(
            msg.meta.af,
            msg.meta.route_type,
            src=msg.routing.dest,  # their dest = our src
            dest=msg.meta.src,  # their src = our dest
            same_machine=msg.meta.same_machine,
            plugin_name=msg.meta.plugin_name,
        )
        plugin.set_addrs(msg.routing.dest_map, msg.meta.src_map)
        # set_inbound_pipes overrides plugin.plugin_id to the peer's
        # session id (msg.meta.pipe_id) so both sides share one key.
        # create_plugin already inserted under the fresh random id; re-key
        # self.plugins to the peer-supplied id so retransmit-guard lookups
        # in recv_signal_msg (which key on msg.meta.pipe_id) actually hit.
        # Without this rekey, every retransmit creates a NEW plugin and
        # TURN spams a follow-up TURNMsg on each re-entry.
        old_id = plugin.plugin_id
        plugin.set_inbound_pipes(self.inbound_pipes, msg.meta.pipe_id)
        if old_id != plugin.plugin_id and old_id in self.plugins:
            self.plugins.pop(old_id, None)
            self.plugins[plugin.plugin_id] = plugin
        return plugin

    # Use signal router to send a message to the destination.
    async def send_signal(self, msg, plugin, relay_no=2):
        """Encrypt and deliver a signalling message to the peer via the MQTT router."""
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
                    "src_index": plugin.src["if_index"],
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
                    "dest_index": plugin.dest["if_index"],
                }
            )

            # Convert to bytes and send via MQTT.
            buf = to_s(sig_msg_to_buf(msg, h_to_b(plugin.dest_map["pub_key_hex"])))
            await plugin.sig_pipe.send(buf)
        except (OSError, ConnectionError, asyncio.TimeoutError) as exc:
            log_exception()

    # Receive a signal message from the router and pass it to a plugin.
    # Called by the MQTT client as: handler(msg, src_pk, queue_id, client)
    async def recv_signal_msg(self, msg, src_pk_hex, pipe_id_hex, client):
        """Decrypt an incoming signal message and dispatch it to the matching or new plugin."""
        msg = try_unpack_msg(to_b(msg), self.kp.private_key, self.sig_proto)

        # Message has expired.
        if int(self.router.get_time()) >= msg.meta.ttl:
            now = int(self.router.get_time())
            skew = now - msg.meta.ttl
            # log() so this also lands in aionetiface logs -- when this
            # fires it's almost always a sender/receiver clock-skew bug
            # rather than a genuinely-stale message, and stdout output
            # is easy to miss across a 6-VM matrix run.
            from aionetiface import log, fstr
            log(fstr(
                "[SIG-RX] ConMsg EXPIRED: ttl={0} now={1} skew={2}s "
                "wire_name={3} pipe_id={4}; dropping. If skew is large "
                "the sender's sys_clock is probably drifted vs ours -- check "
                "NTP sync on both peers.",
                (msg.meta.ttl, now, skew,
                 repr(getattr(msg, "wire_name", "?")),
                 repr(getattr(msg.meta, "pipe_id", "?"))),
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
        if handler is not None:
            handler(self, msg)
            return

        # If plugin exists check sender is authorized to reach plugin.
        if msg.meta.pipe_id in self.plugins:
            plugin = self.plugins[msg.meta.pipe_id]
            if src_pk_hex != plugin.dest_map["pub_key_hex"]:
                raise ValueError("src_pk_hex mismatch for existing plugin.")
            # Retransmit of an already-resolved signal — peer's republish
            # loop hasn't received the ACK yet; nothing to do.
            if plugin.result.done():
                return

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
        task = get_running_loop().create_task(
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
    def resolve_inbound_by_plugin_id(self, plugin_id, pipe):
        """Resolve the reverse_connect inbound future for plugin_id with pipe."""
        fut = self.inbound_pipes.get(plugin_id)
        if fut is None:
            return
        if fut.done():
            return
        fut.set_result(pipe)

    async def close(self):
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
        """Periodically scan for expired plugins and close them to free resources."""
        while True:
            await asyncio.sleep(5)
            try:
                now = get_running_loop().time()
                for plugin in list(self.plugins.values()):
                    expires_at = getattr(plugin, "expires_at", None)
                    if expires_at is None:
                        log("[TM] cleanup_loop: plugin missing expires_at, skipping")
                        continue
                    if now >= expires_at:
                        try:
                            await close_plugin(plugin, self.plugins, self.inbound_pipes)
                        except asyncio.CancelledError:
                            raise
                        except (OSError, asyncio.TimeoutError):
                            log_exception()
            except asyncio.CancelledError:
                raise
            except (OSError, AttributeError, asyncio.TimeoutError):
                log_exception()

    def install_plugin_done_callback(self, done_callback):
        """Register a callback to be invoked when any plugin finishes."""
        self.done_callback = done_callback

