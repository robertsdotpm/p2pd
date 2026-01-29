import socket
import selectors

NODE_PORT = 10001
TRY_OVERLAP_EXTS = 1
TRY_NOT_TO_OVERLAP_EXTS = 2
CON_ID_MSG = b"P2P_CON_ID_EQ"

# No more than n interfaces per address family in peer addr.
NODE_ADDR_MAX_INTERFACES = 4

# No more than n signal pipes to send signals to nodes.
SIGNAL_PIPE_NO = 1 # TODO: change back to 3

# create socket pair
stop_rw = socket.socketpair()
stop_rw[0].setblocking(False)

NODE_CONF = {
    "reuse_addr": False,
    "enable_upnp": True,
    "sig_pipe_no": SIGNAL_PIPE_NO,
    "install_path": None,
    "init_clock_skew": True,
    "enable_punching": True,
    "enable_nickname": True,
    "enable_stun_clients": True,

}

NODE_TEST_CONF =  {
    "reuse_addr": False,
    "enable_upnp": False,
    "sig_pipe_no": 0,
    "install_path": None,
    "init_clock_skew": False,
    "enable_punching": True,
    "enable_nickname": False,
    "enable_stun_clients": False,
}