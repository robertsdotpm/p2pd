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
"""

from collections import OrderedDict
from ..utility.utils import *
from ..net.net_defs import *
from ..nic.interface import *
from .tunnel_utils import *

class TraversalPlugin():
    def __init__(self):
        pass

    def set_routing(self, af, src_info, dest_info, nic):
        self.af = af
        self.src_info = src_info
        self.dest_info = dest_info
        self.nic = nic

        # Ensure our selected NIC is what the
        # remote peer wanted to use for the technique.
        """
        if reply is not None:
            if reply.routing.dest_index != src_info["if_index"]:
                raise Exception("Invalid NIC loaded for plugin.")
        """
            
    def set_context(self, route_type, same_machine, set_bind, timeout):
        self.route_type = route_type
        self.same_machine = same_machine
        self.set_bind = set_bind
        self.timeout = timeout

        """
        Determine the best destination IP to use
        for the connectivity technique based on
        addressing and relationships between the
        two machines (deep networking specific.)
        """
        self.dest_info["ip"] = str(
            select_dest_ipr(
                self.af,
                same_machine,
                self.src_info,
                self.dest_info,
                [route_type],

                # can you make this case
                # run for all
                # try it
                set_bind,
            )
        )

        # Need a destination address.
        # Possibly a different address type will work.
        if self.dest_info["ip"] == "None":
            raise Exception("Cannot select valid dest IP")

    def set_pipe_id(self, pipe_id, pipe_future):
        self.pipe_id = pipe_id
        self.pipe_future = pipe_future

    async def run(self, reply=None):
        print("run parent.")

class TraversalManager():
    def __init__(self, pipes={}, nic_map={}):
        self.plugin_loaders = OrderedDict()
        self.plugins = {} # by pipe id
        self.pipes = pipes # by pipe id
        self.nic_map = nic_map

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
    
    async def close_plugin(self, plugin, reply=None):
        # Delete unused futures on failure.
        if hasattr(plugin, "pipe_id"):
            del self.plugins[plugin.pipe_id]
            del self.pipes[plugin.pipe_id]

    async def plugin_router(self, af, route_type, src_info, dest_info, same_machine, plugin_name, reply=None):
        # Meta data for this specific plugin.
        plugin_loader = self.plugin_loaders[plugin_name]

        # New instance of the plugin using init.
        plugin = plugin_loader["class"]()
        print(plugin_loader)
        print(plugin)

        # Load routing details in plugin.
        nic = self.nic_map.get(src_info["if_index"], None)
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

        # Run plugin function -- has timeout based on plugin meta.
        pipe = await self.run_plugin(plugin, reply)
        if pipe: return pipe

    async def connect(self, src_map, dest_map, af=IP4, route_type=NIC_BIND):
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
        for plugin_name in self.plugin_loaders:
            print(plugin_name)
            for if_infos in if_infos_order:
                src_info, dest_info = if_infos
                pipe = await self.plugin_router(
                    af,
                    route_type,
                    src_info,
                    dest_info,
                    same_machine,
                    plugin_name
                )

                # Run plugins for if info pairs.
                if pipe:
                    return pipe


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
        manager = TraversalManager()
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


        await manager.connect(ADDR_MAP, ADDR_MAP)

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


