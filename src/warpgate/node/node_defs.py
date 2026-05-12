"""Constants, data-structures, and defaults for a warpgate node."""
import socket

NODE_PORT = 10001
TRY_OVERLAP_EXTS = 1
TRY_NOT_TO_OVERLAP_EXTS = 2

# No more than n interfaces per address family in peer addr.
NODE_ADDR_MAX_INTERFACES = 4

# No more than n signal pipes to send signals to nodes.
SIGNAL_PIPE_NO = 1


def make_stop_pipe():
    """Return a fresh (reader, writer) socketpair used to signal a node to stop.

    The reader is non-blocking; the writer is blocking. Call this at the
    initialisation point of whatever needs a stop channel -- avoid using a
    shared module-level pair, which creates import-time side effects and
    makes cleanup fragile.
    """
    stop_rw = socket.socketpair()
    stop_rw[0].setblocking(False)
    stop_rw[1].setblocking(True)
    return stop_rw


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

NODE_TEST_CONF = {
    # SO_REUSEADDR=True for tests so back-to-back runs can rebind the
    # same listen port even when the previous run's socket is still
    # in TIME_WAIT (Linux holds it ~60s, longer than the gap between
    # two consecutive test subprocesses). Production NODE_CONF keeps
    # this False so an accidentally double-started node fails fast
    # instead of silently shadowing an existing one.
    "reuse_addr": True,
    "enable_upnp": False,
    "sig_pipe_no": 0,
    "install_path": None,
    "init_clock_skew": False,
    "enable_punching": True,
    "enable_nickname": False,
    "enable_stun_clients": False,
}
