import os, sys, logging, traceback, threading, queue

IS_DEBUG = "P2PD_DEBUG" in os.environ

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
    handler = logging.FileHandler(log_path, mode='a', encoding='utf-8')
    formatter = logging.Formatter('[%(filename)s:%(lineno)d] %(message)s', '%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.DEBUG)

def _log_worker():
    """Background thread consuming the log queue."""
    while True:
        message = _log_queue.get()
        if message is _stop_sentinel:
            break
        try:
            logging.info(str(message))
            for h in logging.getLogger().handlers:
                h.flush()
        except Exception:
            pass
        finally:
            _log_queue.task_done()

def start_logger():
    """Start the background thread."""
    global _log_thread
    if not IS_DEBUG or _log_thread is not None:
        return
    _log_thread = threading.Thread(target=_log_worker, daemon=True)
    _log_thread.start()

def stop_logger():
    """Stop the background thread gracefully."""
    global _log_thread
    if not IS_DEBUG or _log_thread is None:
        return
    _log_queue.put(_stop_sentinel)
    _log_thread.join()
    _log_thread = None

def log(message):
    """Enqueue a message to be logged."""
    if not IS_DEBUG:
        return
    _log_queue.put(message)

def log_exception():
    """Log current exception."""
    exc_type, exc_value, exc_tb = sys.exc_info()
    try:
        if exc_tb:
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            lineno = exc_tb.tb_lineno
        else:
            fname, lineno = "unknown", 0
        exc_text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        log("> {0}, line {1} = {2}".format(fname, lineno, exc_text))
    except Exception:
        pass
