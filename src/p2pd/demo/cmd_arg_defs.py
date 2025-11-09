import argparse
from ..do_imports import *
from .defs import *

"""
parser.add_argument("--stun_server", type=str, required=False, help="Specify using a specific STUN server")
parser.add_argument("--ntp_server", type=str, required=False, help="Specify using a specific STUN server")
"""

parser = argparse.ArgumentParser(description="A simple greeting script")
parser.add_argument("--nics", type=str, required=False, help="Limit to specific nics, comma separated")
parser.add_argument("--port", type=int, required=False, help="Start node on specific port")
parser.add_argument("--pnp_server", type=str, required=False, help="Specify using a specific PNP server")
parser.add_argument("--turn_server", type=str, required=False, help="Specify using a specific TURN server")
parser.add_argument("--mqtt_server", type=str, required=False, help="Specify using a specific STUN server")
parser.add_argument("--dest_addr", type=str, required=False, help="Destination to connect to")
parser.add_argument("--echo", type=str, required=False, help="Text to send down the connection")
parser.add_argument("--cmd", type=str, required=False, help="Command to run")
parser.add_argument("--install_path", type=str, required=False, help="Directory path to use to store some of P2PDs data files. Defaults to user home/p2pd")
parser.add_argument("--disable_upnp", type=str, required=False, help="Disable port forwarding and IPv6 pin hole rules on an associated router?")
args = parser.parse_args()
