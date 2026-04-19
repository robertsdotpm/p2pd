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

import hashlib
import asyncio
from collections import OrderedDict
from aionetiface import *
from .traversal_utils import *
from .traversal_plugin import TraversalPlugin
from ..protocol.traversal.proto_msg import GetAddr, ConMsg, ProtoMsg, SIG_PROTO

class TraversalManager():
    def __init__(self, router, stop_reader, inbound_pipes=None, nics=None):
        self.router = router
        self.stop_reader = stop_reader
        self.vk = None        # Set after cryptography is loaded.
        self.sk = None        # Set after cryptography is loaded.
        self.addr_bytes = None  # Set after node address is built.
        self.plugin_loaders = OrderedDict()
        self.plugins = {}   # by plugin_id
        self.inbound_pipes = inbound_pipes if inbound_pipes else {}
        self.nics = nics if nics else []
        self.done_callback = None
        self.tasks = []     # Long-lived background tasks spawned by signal handling.

    def install_plugin_done_callback(self, done_callback):
        self.done_callback = done_callback
    
    def set_signal_msg_sender(self, signal_msg_sender):
        self.signal_msg_sender = signal_msg_sender

    def install_plugin(self, name, conf):
        assert("class" in conf)
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

        await async_wrap_errors(
            plugin.run(reply),
            timeout=plugin.timeout
        )

    def plugin_router(self, af, route_type, src_info, dest_info, same_machine, plugin_name):
        # Meta data for this specific plugin.
        plugin_loader = self.plugin_loaders[plugin_name]

        # New instance of the plugin using init.
        plugin_class = plugin_loader["class"]
        if hasattr(plugin_class, "build_plugin"):
            plugin = plugin_class.build_plugin()
        else:
            plugin = plugin_class()

        plugin.stop_reader = self.stop_reader
        self.plugins[plugin.plugin_id] = plugin

        # Install done callback handler.
        if self.done_callback:
            plugin.result.add_done_callback(self.done_callback)

        # When the plugin's result resolves (punch succeeded, direct-connect
        # returned, etc.) schedule a cleanup so stale entries in self.plugins
        # and plugin-internal state (punch tasks) don't accumulate across
        # multiple attempts in the same session.
        def _schedule_plugin_cleanup(future, _plugin=plugin):
            try:
                asyncio.get_event_loop().create_task(self.close_plugin(_plugin))
            except RuntimeError:
                pass  # Event loop closed during shutdown.
        plugin.result.add_done_callback(_schedule_plugin_cleanup)

        # Allows plugins to await on pipes from other places.
        plugin.set_inbound_pipes(self.inbound_pipes)

        # Load routing details in plugin.
        nic = self.nics[src_info["if_index"]]
        plugin.set_routing(
            af,
            src_info,
            dest_info,
            nic
        )

        # Load extra info about pathway.
        plugin.set_context(
            route_type,
            same_machine,
            plugin_loader["set_bind"],
            plugin_loader["timeout"]
        )

        # Set function for plugin to send signaling replies.
        plugin.set_signal_msg_sender(self.signal_msg_sender)

        return plugin
    
    def get_plugin(self, msg):
        """
        Edge-case where you're connecting to yourself.
        """
        if msg.meta.pipe_id in self.plugins: # and not msg.meta.same_machine
            plugin = self.plugins.get(msg.meta.pipe_id)
        else:
            # TODO: map GetAddr messages to the return_addr plugin handler.
            if isinstance(msg, ConMsg):
                msg.meta.plugin_name = "direct_connect"

            # Check plugin name exists.
            if msg.meta.plugin_name not in self.plugin_loaders:
                raise Exception("Plugin not installed.")

            # Load new instance to handle this message.
            plugin = self.plugin_router(
                msg.meta.af,
                msg.meta.route_type,
                
                # We become the new source.
                src_info=msg.routing.dest_info,

                # They become the new dest.
                dest_info=msg.meta.src_info,
                same_machine=msg.meta.same_machine,
                plugin_name=msg.meta.plugin_name
            )

            # Swap source and dest around.
            plugin.set_addrs(msg.routing.dest, msg.meta.src)

            # Reuse the same plugin_id from the incoming message.
            plugin.set_inbound_pipes(self.inbound_pipes, msg.meta.pipe_id)

        return plugin

    async def start(self, src_map, dest_map, sig_pipe, plugin_name, af=IP4, route_type=NIC_BIND):
        # Need AF supported by both.
        if not src_map[af] or not dest_map[af]:
            raise Exception("AF not supported between hosts.")
        
        # Is this a connection to a node on the same machine?
        if dest_map["machine_id"] == src_map["machine_id"]:
            same_machine = True
        else:
            same_machine = False
        
        # Pairs of (src_info, dest_info) based on src / dest map.
        if_infos_order = get_if_infos_order(
            af,
            route_type,
            src_map,
            dest_map
        )

        # Try every interface info pair for the plugins.
        for if_infos in if_infos_order:
            src_info, dest_info = if_infos
            plugin = self.plugin_router(
                af,
                route_type,
                src_info,
                dest_info,
                same_machine,
                plugin_name
            )

            # Load overall addr info into the plugin.
            plugin.set_addrs(src_map, dest_map)

            # Used to communicate on MQTT.
            plugin.sig_pipe = sig_pipe

            # Run plugin function -- timeout based on plugin meta.
            await self.run_plugin(plugin)
            return plugin
                
    async def close_plugin(self, plugin, reply=None):
        # Delete unused futures on failure.
        # Use pop() so a double-close or a pipe that was never registered
        # does not raise KeyError and abort the cleanup.
        if hasattr(plugin, "plugin_id"):
            self.plugins.pop(plugin.plugin_id, None)
            self.inbound_pipes.pop(plugin.plugin_id, None)

        # Delegate to plugin-specific cleanup (e.g. PunchPlugin cancels its
        # background punch task and clears shared punch_clients/punch_proc).
        close_fn = getattr(plugin, "close", None)
        if callable(close_fn):
            try:
                result = close_fn()
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                log_exception()

    async def signal_msg_sender(self, msg, plugin, relay_no=2):
        try:
            msg.meta = ProtoMsg.Meta.from_dict({
                "ttl": int(self.router.get_time()) + 30,
                "pipe_id": plugin.plugin_id,
                "af": plugin.af,
                "src_buf": plugin.src_map["bytes"],
                "src_index": plugin.src_info["if_index"],
                "route_type": plugin.route_type,
                "same_machine": plugin.same_machine,
                "plugin_name": msg.meta.plugin_name,
            })

            msg.routing = ProtoMsg.Routing.from_dict({
                "af": plugin.af,
                "dest_buf": plugin.dest_map["bytes"],
                "dest_index": plugin.dest_info["if_index"],
            })

            # Attach our compressed verifying key so the receiver can decrypt.
            msg.cipher.vk = self.vk.to_string("compressed")

            # Convert to bytes and send via MQTT.
            buf = to_s(sig_msg_to_buf(msg))
            print("sending ", msg.to_dict())
            await plugin.sig_pipe.send(buf)
        except Exception:
            log_exception()

    async def close(self):
        """Cancel all background tasks and clean up all registered plugins.

        Iterates a snapshot of self.plugins so that close_plugin() can safely
        mutate the dict (via pop) while we iterate.
        """
        # Close each plugin: cancels background punch tasks, clears shared
        # state, and cancels any unresolved result futures.
        for plugin in list(self.plugins.values()):
            try:
                await self.close_plugin(plugin)
            except Exception:
                log_exception()

        # Cancel background signal-handler tasks spawned by handle_router_msg.
        live = [t for t in self.tasks if not t.done()]
        for t in live:
            t.cancel()
        if live:
            await asyncio.gather(*live, return_exceptions=True)
        self.tasks.clear()

    # Receive a signal message and pass it to a plugin.
    # Called by the MQTT client as: handler(msg, src_pk, queue_id, client)
    async def handle_router_msg(self, msg, src_pk_hex, pipe_id_hex, client):
        try:
            buf = to_b(msg)
            msg = try_unpack_msg(buf, self.sk, SIG_PROTO)
            print("recv ", msg.to_dict())

            # TODO: re-enable TTL check once clock skew handling is solid.
            # if int(self.router.get_time()) >= msg.meta.ttl:
            #     raise Exception("Discarding expired msg.")

            # Update routing destination with our current address.
            msg.set_cur_addr(self.addr_bytes)

            # Dispatch to the matching (or new) plugin.
            plugin = self.get_plugin(msg)
        except Exception:
            what_exception()
            log_exception()
            return
        
        # Route to destination via MQTT.
        if plugin.sig_pipe is None:
            plugin.sig_pipe = await self.router.pipe(
                plugin.dest_map["pub_key_hex"],
                use_cache=True
            )

        # Schedule the plugin run as a background task.
        # Keep a reference so the task isn't garbage-collected mid-run.
        task = asyncio.create_task(
            async_wrap_errors(
                self.run_plugin(plugin, reply=msg)
            )
        )
        self.tasks.append(task)
        # Prune completed tasks to avoid unbounded growth.
        self.tasks = [t for t in self.tasks if not t.done()]

if __name__ == "__main__":

    async def setup_node_quick():
        from p2pd.nic.select_interface import list_interfaces
        from p2pd.nic.interface_utils import load_interfaces
        from p2pd.node.node import get_p2pd_install_root, NET_CONF, Node

        # Load interfaces on machine.
        if_names = await list_interfaces()
        ifs = await load_interfaces(
            if_names,
            Interface,
            min_agree=1,
            max_agree=2 ,
            timeout=4
        )

        node_conf = dict_child({
            "init_clock_skew": False,
            "reuse_addr": False,
            "enable_upnp": False,
            "sig_pipe_no": 0,
            "enable_punching": False,
            "enable_nickname": True,
            "enable_stun_clients": False,
            "install_path": get_p2pd_install_root()
        }, NET_CONF)


        # Main node class with chosen ifs and conf.
        node = Node(ifs=ifs, conf=node_conf)

        # Start the node and install echo protocol handler.
        await node.start(out=True)

        addr = node.addr_map
        await node.close()
        return addr


    ADDR_MAP = {IP4: {0: {'netiface_index': 1, 'if_index': 0, 'ext': "45.118.0.1", 'nic': "10.0.1.251", 'nat': {'type': 5, 'delta': {'type': 6, 'value': 0}, 'range': [1, 65535], 'is_open': False, 'can_predict': True, 'is_hard': True, 'is_concurrent': True}, 'port': 3000}}, IP6: {}, 'node_id': '7f9ca6a685ecb37d77057fd02', 'signal': (), 'machine_id': '7a64285df710807300863496142f032a5b2365ce6a4a11f9b400fc1e6b4326e5', 'bytes': b'None-[1,0,45.118.0.1,10.0.1.251,3000,5,6,0]-0-7f9ca6a685ecb37d77057fd02-7a64285df710807300863496142f032a5b2365ce6a4a11f9b400fc1e6b4326e5'}

    class PluginDirect(TraversalPlugin):
        pass

    class PluginPunch(TraversalPlugin):
        pass


    async def tunnel_workspace():
        manager = TraversalManager(nics=[None])
        manager.install_plugin("direct", {
            "class": PluginDirect,
            "timeout": 2,
            "cleanup": None,
            "set_bind": 1,
            "max_pairs": 6,
        })

        manager.install_plugin("punch", {
            "class": PluginPunch,
            "timeout": 2,
            "cleanup": None,
            "set_bind": 1,
            "max_pairs": 6,
        })

        print(manager.plugins)
        #addr = await setup_node_quick()
        #print(addr)


        await manager.start(ADDR_MAP, ADDR_MAP)

        #await tunnel_factory()

        return
        nic = await Interface()
        src_info = dest_info = {
            "af": IP4,
            "if_index": 0,
        }
        p = Plugin(src_info, dest_info, nic)
        print(p)

    async_run(tunnel_workspace())


