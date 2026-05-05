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
    help=(
        "IP address(es) to listen on. Restricts the bind set to exactly "
        "these IPs (per AF). The published node address still advertises "
        "the full per-NIC surface from make_node_addr -- including v6 "
        "link-locals -- so passing a v6 global here without also passing "
        "the link-local leaves peers unable to reach the link-local NIC "
        "slot (TCP RST). Prefer --nic alone unless you need the strict "
        "bind narrowing; --nic alone leaves listen_ips empty and lets "
        "listen_on_ifs bind the full per-NIC surface that the addr "
        "advertises."
    ),
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
    "--id",
    dest="node_id",
    type=str,
    required=False,
    default=None,
    help=(
        "Stable node identity. The signing-key file on disk is keyed by "
        "this name -- so the same --id always loads the same keypair, "
        "regardless of NIC / IP / port. Two nodes that pass the same --id "
        "(even on different hosts) will share a private key and clash on "
        "the PNP slot, so use distinct names per node. When omitted, "
        "falls back to a single shared 'default' identity at the install "
        "path -- fine for single-node hosts, will collide between two "
        "instances on one box without --id."
    ),
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
parser.add_argument(
    "--verify_install",
    action="store_true",
    help=(
        "Strictly verify all four sibling repos (aionetiface, p2pd, "
        "sidewire, namebump) imported from a consistent install root "
        "and not from site-packages. Aborts with a clear error if any "
        "sibling diverges -- catches stale wheel shadows and partial "
        "path divergences that otherwise produce silent KeyError on "
        "plugin lookup."
    ),
)
# Bare `python -m p2pd.demo` with no flags runs the interactive menu
# with default settings. argparse handles -h / --help on its own (prints
# help and exits 0), so users who want to discover flags still can.
args = parser.parse_args()
