"""
if ~/p2pd/logs exists -- write logs
otherwise do nothing
"""

import os
import sys
import traceback
import os
import threading
from .fstr import *
from ..install import get_p2pd_install_root

LOGS_ROOT_PATH = os.path.join(
    get_p2pd_install_root(),
    "logs"
)

log_fds = {}

def open_log_fd(tid):
    if tid not in log_fds:
        path = os.path.join(
            LOGS_ROOT_PATH,
            "p2pd_" + str(os.getpid()) + "_" + str(tid) + ".log"
        )
        
        log_fds[tid] = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o644
        )
        
    return log_fds[tid]

def log(msg):
    if not os.path.exists(LOGS_ROOT_PATH):
        return

    tid = threading.get_ident()
    fd = open_log_fd(tid)
    os.write(fd, msg.encode("utf-8") + b"\n")

def log_exception():
    exc = "".join(traceback.format_exception(*sys.exc_info()))
    log("EXCEPTION: " + exc.strip())

def log_p2p(msg, node_id):
    log(fstr("p2p <{0}>: {1}", (node_id, msg)))