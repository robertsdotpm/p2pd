import os
import sys
import logging
import traceback
import threading
import queue
from .fstr import *

IS_DEBUG = "P2PD_DEBUG" in os.environ

# Global state
logging_queue = queue.Queue()
logging_thread = None
app_logger = None

def init_logger():
    global app_logger
    log_path = "program.log"
    for arg in sys.argv:
        if arg.startswith("--log_path="):
            log_path = arg.split("=", 1)[1]
            break

    log_path = os.path.abspath(log_path)
    logger = logging.getLogger("p2pd")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    if not any(
        isinstance(h, logging.FileHandler) and h.baseFilename == log_path
        for h in logger.handlers
    ):
        handler = logging.FileHandler(log_path, "a", encoding="utf-8")
        handler.setFormatter(
            logging.Formatter(
                "[%(filename)s:%(lineno)d] %(message)s",
                "%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(handler)

    app_logger = logger

def log_worker():
    try:
        logger = app_logger
        while True:
            # Blocking call, waits indefinitely for an item
            msg = logging_queue.get()

            # Exit signal check
            if msg is None:
                break
            
            # Write to log
            if logger:
                logger.info(str(msg))
    except Exception:
        return

def start_logger():
    global logging_thread
    
    if not IS_DEBUG or logging_thread is not None:
        return

    init_logger()
    logging_thread = threading.Thread(target=log_worker, daemon=True)
    logging_thread.start()

def log(msg):
    global logging_queue
    if not IS_DEBUG:
        return

    #print(msg)
    logging_queue.put_nowait(msg)

def log_exception():
    if not IS_DEBUG:
        return

    exc = "".join(traceback.format_exception(*sys.exc_info()))
    log("EXCEPTION: " + exc.strip())

def log_p2p(msg, node_id):
    log(fstr("p2p <{0}>: {1}", (node_id, msg)))