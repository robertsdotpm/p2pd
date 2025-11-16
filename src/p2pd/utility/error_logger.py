import os
import sys
import logging
import traceback
import threading
import queue
import atexit
from .fstr import *
from ..node.node_defs import *

# --- Configuration & Initialization ---
IS_DEBUG = "P2PD_DEBUG" in os.environ

# 1. Cleaner Log Path Setup (Kept simple, but noted argparse is an option)
log_path = "program.log"
for arg in sys.argv:
    if "--log_path=" in arg:
        log_path = arg.split("--log_path=")[1]
        break

log_path = os.path.abspath(log_path)
_log_queue = queue.Queue()
_log_thread = None
_stop_sentinel = object()

if IS_DEBUG:
    # Standard Python logging setup
    handler = logging.FileHandler(log_path, mode='a', encoding='utf-8')
    handler.setFormatter(
        logging.Formatter(
            '[%(filename)s:%(lineno)d] %(message)s',
            '%Y-%m-%d %H:%M:%S'
        )
    )
    
    # Get the root logger
    logger = logging.getLogger()
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

# --- Core Worker Thread ---
def _log_worker():
    """Background thread consuming the log queue."""
    # We rely on the existing handlers attached to the root logger
    logger = logging.getLogger()
    while not shutdown_event.is_set():
        # Blocks until a message is available
        message = _log_queue.get() 
        if message is _stop_sentinel:
            # Drain the queue before exiting (optional, but safer)
            break # Exit the loop and thread
        try:
            # Use logging.info() to the configured FileHandler
            logging.info(str(message))
            
            # Flush the handlers. This is essential for log file immediacy.
            # Cleaner than iterating over getLogger().handlers
            for h in logger.handlers: 
                h.flush()
        except Exception:
            # Catching and suppressing errors during logging itself (robustness)
            pass
        finally:
            _log_queue.task_done()

# --- Public Interface and Lifecycle ---
def start_logger():
    """
    Start the background thread and register the stop function.
    The thread is daemon=True, but atexit ensures graceful shutdown on normal exit.
    """
    global _log_thread
    if not IS_DEBUG or _log_thread is not None:
        return
        
    _log_thread = threading.Thread(target=_log_worker, daemon=True)
    _log_thread.start()
    
    # 2. Use atexit for Graceful Shutdown
    atexit.register(stop_logger)

def stop_logger():
    """Stop the background thread gracefully by sending a sentinel and joining."""
    global _log_thread
    if not IS_DEBUG or _log_thread is None:
        return
        
    # Send sentinel to unblock the worker thread
    _log_queue.put(_stop_sentinel)
    
    # Wait for the worker thread to finish processing and exit
    _log_thread.join()
    _log_thread = None
    
    # Unregister to prevent re-running if stop_logger is called multiple times
    try:
        atexit.unregister(stop_logger)
    except AttributeError:
        # unregister isn't available in Python < 3.8
        pass 

def log(message):
    """Enqueue a message to be logged."""
    if not IS_DEBUG:
        return
    _log_queue.put(message)

def log_exception():
    """Log current exception."""
    if not IS_DEBUG:
        return
        
    exc_type, exc_value, exc_tb = sys.exc_info()
    
    # Use standard library formatting for the traceback
    exc_text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    
    # Enqueue the formatted string
    log("EXCEPTION: " + exc_text.strip())

def log_p2p(msg, node_id):
    buf = fstr("p2p <{0}>: {1}", (node_id, msg,))
    log(buf)