
import sys

"""
This is a hack to avoid double-imports of a module when using
the -m switch to run a module directly. Python modules are lolz.
"""
if '-m' not in sys.argv:
    from .address import Address
    from .base_stream import SUB_ALL, pipe_open
    from .clock_skew import SysClock
    from .cmd_tools import *
    from .daemon import Daemon
    from .errors import *
    from .http_client_lib import ParseHTTPResponse, http_req, http_req_buf
    from .http_server_lib import (ParseHTTPRequest, rest_service, send_binary,
                                  send_json)
    from .interface import Interface, Interfaces, init_p2pd
    from .ip_range import IPRange
    from .net import *
    from .p2p_addr import *
    from .p2p_node import P2PNode
    from .p2p_pipe import *
    from .p2p_utils import get_pp_executors, start_p2p_node
    from .rest_api import P2PDServer, start_p2pd_server
    from .route import Route, RoutePool, Routes
    from .stun_client import STUNClient
    from .tcp_punch import TCPPunch
    from .turn_client import TURNClient
    from .upnp import port_forward
    from .utils import async_test, log, log_exception, what_exception
