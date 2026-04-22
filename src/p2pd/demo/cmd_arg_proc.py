"""CLI argument processing for the p2pd demo."""
from aionetiface import PNP_SERVERS
from .defs import demo_node_conf
from .cmd_arg_defs import args
from .utils import patch_server_af_dict, patch_server_list

if args.disable_upnp:
    demo_node_conf["enable_upnp"] = False

if args.pnp:
    patch_server_af_dict(args.pnp, PNP_SERVERS)

if args.mqtt:
    patch_server_list(args.mqtt, MQTT_SERVERS)

if args.cmd == "get_nickname":
    demo_node_conf["sig_pipe_no"] = 0
    demo_node_conf["enable_upnp"] = False
    demo_node_conf["init_clock_skew"] = False
    demo_node_conf["enable_punching"] = False
    # node_conf["enable_nickname"] = False

if args.install_path:
    demo_node_conf["install_path"] = args.install_path
