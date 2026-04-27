"""CLI argument definitions for the p2pd demo."""
import argparse
from ..node.node_defs import NODE_PORT

# parser.add_argument("--stun_server", type=str, required=False,
#     help="Specify using a specific STUN server")
# parser.add_argument("--ntp_server", type=str, required=False,
#     help="Specify using a specific STUN server")

parser = argparse.ArgumentParser(description="P2P args")
parser.add_argument(
    "--nic",
    action="append",
    default=[],
    required=False,
    help="Limit to specific nics, comma separated",
)
parser.add_argument(
    "--port",
    type=int,
    required=False,
    default=NODE_PORT,
    help="Start node on specific port",
)
parser.add_argument(
    "--ip",
    action="append",
    default=[],
    help="IP address(es) to listen on",
)
parser.add_argument(
    "--pnp",
    action="append",
    default=[],
    required=False,
    help="Specify using a specific PNP server",
)


parser.add_argument(
    "--turn",
    type=str,
    required=False,
    help="Specify using a specific TURN server",
)
parser.add_argument(
    "--mqtt",
    type=str,
    required=False,
    help="Specify using a specific STUN server",
)
parser.add_argument(
    "--dest",
    type=str,
    required=False,
    help="Destination to connect to",
)
parser.add_argument(
    "--echo",
    type=str,
    required=False,
    help="Text to send down the connection",
)
parser.add_argument(
    "--cmd",
    type=str,
    required=False,
    help="Command to run",
)
parser.add_argument(
    "--install_path",
    type=str,
    required=False,
    help=(
        "Directory path to use to store some of P2PDs data files. "
        "Defaults to user home/p2pd"
    ),
)
parser.add_argument(
    "--disable_upnp",
    type=str,
    required=False,
    help=("Disable port forwarding and IPv6 pin hole rules on an associated router?"),
)
parser.add_argument(
    "--run_time",
    type=int,
    required=False,
    help="Close automatically after this amount of seconds.",
)
# Bare `python -m p2pd.demo` with no flags runs the interactive menu
# with default settings. argparse handles -h / --help on its own (prints
# help and exits 0), so users who want to discover flags still can.
args = parser.parse_args()
