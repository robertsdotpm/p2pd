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

error_fd = None

def open_log_fd():
    global error_fd
    if error_fd is None:
        path = os.path.join(
            LOGS_ROOT_PATH,
            "".join([
                "p2pd_",
                str(os.getpid()),
                "_",
                threading.get_ident(),
                ".log"
            ]),
        )
        
        error_fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o644,
        )

def log(msg):
    if not os.path.exists(LOGS_ROOT_PATH):
        return

    open_log_fd()
    os.write(error_fd, msg.encode("utf-8") + b"\n")

def log_exception():
    exc = "".join(traceback.format_exception(*sys.exc_info()))
    log("EXCEPTION: " + exc.strip())

def log_p2p(msg, node_id):
    log(fstr("p2p <{0}>: {1}", (node_id, msg)))