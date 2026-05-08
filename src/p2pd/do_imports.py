"""Re-exports the full p2pd public API as a single namespace."""
import os


if __name__ != "__main__":
    os.environ["PYTHONIOENCODING"] = "utf-8"
    from aionetiface import *  # noqa: F401, F403  # pylint: disable=wildcard-import,unused-wildcard-import
    from .errors import *  # noqa: F401, F403  # pylint: disable=wildcard-import,unused-wildcard-import
    from .traversal.plugins.upnp.main import port_forward  # noqa: F401  # pylint: disable=unused-import
    from .traversal.plugins.turn.turn_client import TURNClient  # noqa: F401  # pylint: disable=unused-import
    from .protocol.echo.echo_server import *  # noqa: F401, F403  # pylint: disable=wildcard-import,unused-wildcard-import
    from .node.node import Node, NODE_CONF, NODE_PORT, get_p2pd_install_root  # noqa: F401  # pylint: disable=unused-import
    from .node.node_defs import make_stop_pipe  # noqa: F401  # pylint: disable=unused-import
    from .node.node_utils import get_pp_executors, load_signing_key, load_stun_clients  # noqa: F401  # pylint: disable=unused-import
    from .node.nickname import *  # noqa: F401, F403  # pylint: disable=wildcard-import,unused-wildcard-import
    from .node.node_connect import resolve_pnp_addr  # noqa: F401  # pylint: disable=unused-import
    from .node.auto_connect import auto_connect  # noqa: F401  # pylint: disable=unused-import
    from .traversal.traversal_plugin import Plugin  # noqa: F401  # pylint: disable=unused-import
    from .traversal.strategy_registry import register  # noqa: F401  # pylint: disable=unused-import
    from .gate import Gate, peer, PeerHandle  # noqa: F401  # pylint: disable=unused-import
