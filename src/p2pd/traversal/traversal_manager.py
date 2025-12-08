"""
I think there should be a factory for building Plugins and
each plugin should have a class that has its addressing details
filled in and elegantly encapsulated.

existing tunnel code handles setting up futures
reply structuries
routing replies
cleanup code
logging

it should just focus on addressing / function running for now

for_addr_infos
    being called when a reply comes and it manually specifies a strat
    this is very messy maybe dont have reply a param in this code at all?

just start integration with the most basic plugin first then
work through them

resume plugin run func 
on sig msg recv:
    if pipe_id in manager.plugins:
        plugin = manager.plugins[pipe_id]
        plugin.run(reply=reply)

        # Try select if info based on their chosen offset.
        if reply:
            src_info = src_map[af][reply.routing.dest_index]
            dest_info = dest_map[af][reply.meta.src_index]
            if_infos_order = [[src_info, dest_info]]

todo: set this up after the pipe is done:
    tunnel.node.msg_cb
"""

from collections import OrderedDict
from ..utility.utils import *
from ..net.net_defs import *
from ..nic.interface import *
from .traversal_utils import *
from .plugins.traversal_plugin import TraversalPlugin

class TraversalManager():
    def __init__(self, pipes={}, nics=[]):
        self.plugin_loaders = OrderedDict()
        self.plugins = {} # by pipe id
        self.pipes = pipes
        self.nics = nics
        self.done_callback = None

    def install_plugin_done_callback(self, done_callback):
        self.done_callback = done_callback
    
    def set_signal_msg_sender(self, signal_msg_sender):
        self.signal_msg_sender = signal_msg_sender

    def install_plugin(self, name, conf):
        assert("class" in conf)
        conf = {
            "class": conf["class"],
            "timeout": conf.get("timeout", 4),
            "cleanup": conf.get("cleanup", None),
            "set_bind": conf.get("set_bind", False),
            "max_pairs": conf.get("max_pairs", 6),
        }

        self.plugin_loaders[name] = conf

    """
    plugins directly return pipes, they can await for future results
    if it depends on a reply by awaiting the pipe future where
    the pipe gets set somewhere else
    """
    async def run_plugin(self, plugin, reply=None):
        # Don't run if result is set.
        if plugin.result.done():
            return

        # Set nic fields.
        if reply:
            reply.load_if_extra(self.nics)

        print("in run plugin")
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

        self.plugins[plugin.pipe_id] = plugin
        print(plugin_loader)
        print(plugin)

        # Install done callback handler.
        if self.done_callback:
            plugin.result.add_done_callback(self.done_callback)

        # Allows plugins to await on pipes from other places.
        plugin.set_pipes(self.pipes)

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

        # Set function for plugin to send replies.
        print(self.signal_msg_sender)
        plugin.set_signal_msg_sender(self.signal_msg_sender)
        return plugin
    
    def get_plugin(self, msg):
        if msg.meta.pipe_id in self.plugins:
            plugin = self.plugins.get(msg.meta.pipe_id, None)
        else:
            # Map getaddr message to returnaddr plugin handler.
            if isinstance(msg, GetAddr):
                msg.meta.plugin_name = "return_addr"

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

            # Reuse the same pipe_id.
            plugin.set_pipes(self.pipes, msg.meta.pipe_id)

        return plugin

    async def start(self, src_map, dest_map, plugin_name, af=IP4, route_type=NIC_BIND):
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
        print(plugin_name)
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

            # Run plugin function -- timeout based on plugin meta.
            print("running plugin ", plugin)
            await self.run_plugin(plugin)
            return plugin
                
    async def close_plugin(self, plugin, reply=None):
        # Delete unused futures on failure.
        if hasattr(plugin, "pipe_id"):
            del self.plugins[plugin.pipe_id]
            del self.pipes[plugin.pipe_id]

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

        addr = node.p2p_addr
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


