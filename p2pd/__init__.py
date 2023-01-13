
import sys

"""
This is a hack to avoid double-imports of a module when using
the -m switch to run a module directly. Python modules are lolz.
"""
if not '-m' in sys.argv:
    from .errors import *
    from .utils import log, what_exception, log_exception, async_test
    from .cmd_tools import *
    from .net import *
    from .address import Address
    from .ip_range import IPRange
    from .upnp import port_forward
    from .route import Route, RoutePool, Routes
    from .base_stream import pipe_open, SUB_ALL
    from .interface import Interface, Interfaces, init_p2pd
    from .clock_skew import SysClock
    from .stun_client import STUNClient
    from .turn_client import TURNClient
    from .tcp_punch import TCPPunch
    from .daemon import Daemon
    from .http_client_lib import http_req, ParseHTTPResponse
    from .http_client_lib import http_req_buf
    from .http_server_lib import rest_service, send_json, send_binary
    from .http_server_lib import ParseHTTPRequest
    from .rest_api import P2PDServer, start_p2pd_server
    from .p2p_addr import *
    from .p2p_pipe import *
    from .p2p_node import P2PNode
    from .p2p_utils import get_pp_executors, start_p2p_node
