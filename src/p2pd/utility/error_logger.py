import os
import sys
import traceback
import os
import threading
from .fstr import *
from ..install import get_p2pd_install_root

IS_DEBUG = "P2PD_DEBUG" in os.environ
LOGS_ROOT_PATH = os.path.join(
    get_p2pd_install_root(),
    "logs"
)

if not os.path.exists(LOGS_ROOT_PATH):
    os.mkdir(LOGS_ROOT_PATH)

fd = None
lock = threading.Lock()

def open_log_fd():
    global fd
    if fd is None:
        path = os.path.join(
            LOGS_ROOT_PATH,
            "program_" + str(os.getpid()) + ".log",
        )
        
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o644,
        )

def log(msg):
    open_log_fd()
    with lock:
        os.write(fd, msg.encode("utf-8") + b"\n")

def log_exception():
    if not IS_DEBUG:
        return

    exc = "".join(traceback.format_exception(*sys.exc_info()))
    log("EXCEPTION: " + exc.strip())

def log_p2p(msg, node_id):
    log(fstr("p2p <{0}>: {1}", (node_id, msg)))