from collections import OrderedDict
from ..utility.utils import *
from ..net.net_defs import *
from ..nic.interface import *
from .tunnel_utils import *



"""
I think there should be a factory for building Plugins and
each plugin should have a class that has its addressing details
filled in and elegantly encapsulated.


"""

class Plugin():
    def __init__(self):
        pass

    def set_routing(self, af, src_info, dest_info, nic, reply=None):
        self.af = af
        self.src_info = src_info
        self.dest_info = dest_info
        self.nic = nic

        # Ensure our selected NIC is what the
        # remote peer wanted to use for the technique.
        if reply is not None:
            if reply.routing.dest_index != src_info["if_index"]:
                raise Exception("Invalid NIC loaded for plugin.")
            
    def set_context(self, same_machine, set_bind, timeout):
        self.same_machine = same_machine
        self.set_bind = set_bind
        self.timeout = timeout

class PluginDirect(Plugin):
    pass

class PluginPunch(Plugin):
    pass

def get_if_infos_order(af, route_type, src_map, dest_map):
    """
    Given a list of interface details
    for an address family indexed by interface
    offset return a list of them directly.
    """
    src_infos = list(src_map[af].values())
    dest_infos = list(dest_map[af].values())

    """
    Given two lists of interface details, break them into
    two lists of (src_info, dest_info) pairs. The first
    contains pairs for which both interface details have the
    same ext (external address). The other is non-overlapping,
    where both have different addresses.
    """
    overlap, unique = sort_pairs_by_overlap(
        src_infos,
        dest_infos
    )

    """
    If the route type is external than using the same external
    address for overlapping pairs is likely not to lead to
    a connection since both are behind the same router.
    """
    if route_type == EXT_BIND:
        pair_order = unique + overlap

    """
    For local addresses you want to do the opposite.
    So you're on the same LAN or NIC if on the same machine.
    """
    if route_type == NIC_BIND:
        pair_order = overlap + unique

    return pair_order

class PluginManager():
    def __init__(self, nic_map={}):
        self.plugins = OrderedDict()
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

        self.plugins[name] = conf

    # IP4, EXT_BIND
    async def plugin_connect(self, af, route_type, if_infos):
        for src_info, dest_info in if_infos:
            pass

    async def connect(self, af, route_type, src_map, dest_map, reply=None):
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

        # Try every traversial plugin to create a pipe.
        for plugin_name in self.plugins:
            # Meta data for this specific plugin.
            plugin_loader = self.plugins[plugin_name]

            # Loop over the pair of src_info / dest_infos
            # then try them for each plugin.
            for if_info_pair in if_infos_order:
                # New instance of the plugin using init.
                plugin = plugin_loader["class"]()

                # Load routing details in plugin.
                src_info, dest_info = if_info_pair
                nic = self.nic_map.get(src_info["if_index"], None)
                plugin.set_routing(
                    af, 
                    src_info, 
                    dest_info,
                    nic, 
                    reply
                )

                # Load extra info about pathway.
                plugin.set_context(
                    same_machine,
                    plugin_loader["set_bind"],
                    plugin_loader["timeout"]
                )


                print(plugin_loader)
                print(plugin)


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

if __name__ == "__main__":
    async def tunnel_workspace():
        manager = PluginManager()
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


        await manager.connect(IP4, NIC_BIND, ADDR_MAP, ADDR_MAP)

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


"""
existing tunnel code handles setting up futures
reply structuries
routing replies
cleanup code
logging

it should just focus on addressing / function running for now
"""