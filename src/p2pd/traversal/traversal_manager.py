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
    def __init__(self, pipes={}, nics=[], f_msg_sender=None):
        self.f_msg_sender = f_msg_sender
        self.plugin_loaders = OrderedDict()
        self.plugins = {} # by pipe id
        self.pipes = pipes # by pipe id
        self.nics = nics

    def install_plugin(self, name, conf):
        assert("class" in conf)
        conf = {
            "class": conf["class"],
            "timeout": conf.get("timeout", 5),
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
        # Create a future for pending pipes.
        if reply is None:
            pipe_id = to_s(rand_plain(15))
        else:
            pipe_id = reply.meta.pipe_id

        if pipe_id not in self.pipes:
            self.pipes[pipe_id] = asyncio.Future()
            self.plugins[pipe_id] = plugin

        plugin.set_pipe_id(pipe_id, self.pipes[pipe_id])
        ret = await async_wrap_errors(
            plugin.run(reply),
            timeout=plugin.timeout
        )

        return ret

    async def plugin_router(self, af, route_type, src_info, dest_info, same_machine, plugin_name):
        # Meta data for this specific plugin.
        plugin_loader = self.plugin_loaders[plugin_name]

        # New instance of the plugin using init.
        plugin = plugin_loader["class"]()
        print(plugin_loader)
        print(plugin)

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
        plugin.set_msg_sender(self.f_msg_sender)
        return plugin
    
    async def get_plugin(self, msg):
        if msg.meta.pipe_id in self.plugins:
            plugin = self.plugin.get(msg.meta.pipe_id, None)
        else:
            plugin = await self.plugin_router(
                msg.meta.af,
                msg.meta.route_type,
                msg.meta.src_info,
                msg.meta.dest_info,
                msg.meta.same_machine,
                msg.meta.plugin_name
            )

        return plugin

    async def start(self, src_map, dest_map, af=IP4, route_type=NIC_BIND, plugin_name=None):
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

        # Set plugins to try.
        if plugin_name:
            plugin_names = (plugin_name,)
        else:
            plugin_names = self.plugin_loaders

        # Try every interface info pair for the plugins.
        for plugin_name in plugin_names:
            print(plugin_name)
            for if_infos in if_infos_order:
                src_info, dest_info = if_infos
                plugin = await self.plugin_router(
                    af,
                    route_type,
                    src_info,
                    dest_info,
                    same_machine,
                    plugin_name
                )

                # Load overall addr info into the plugin.
                plugin.set_addrs(src_map, dest_map)

                # Run plugin function -- has timeout based on plugin meta.
                pipe = await self.run_plugin(plugin)

                # Run plugins for if info pairs.
                if pipe:
                    return pipe
                
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


