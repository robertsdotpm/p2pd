# error_logger.py
import os
import sys
import logging
import traceback
import asyncio

IS_DEBUG = "P2PD_DEBUG" in os.environ

log_path = 'program.log'
for arg in sys.argv:
    if "--log_path=" in arg:
        log_path = arg.split("--log_path=")[1]
        break

log_path = os.path.abspath(log_path)

if IS_DEBUG:
    logging.basicConfig(
        filename=log_path,
        level=logging.DEBUG,
        format='[%(filename)s:%(lineno)d] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

# Global queue for logging
_log_queue = asyncio.Queue()
_log_task = None

async def _log_worker():
    """Background coroutine that consumes the log queue."""
    while True:
        message = await _log_queue.get()
        if message is None:
            break  # sentinel to stop the worker
        try:
            logging.info(str(message))
        except Exception:
            # never raise in logging
            pass
        _log_queue.task_done()

def start_logger(loop=None):
    """Start the background logging task."""
    global _log_task
    if not IS_DEBUG:
        return
    if _log_task is None:
        if loop is None:
            loop = asyncio.get_event_loop()
        _log_task = loop.create_task(_log_worker())

async def stop_logger():
    """Stop the logging worker gracefully."""
    global _log_task
    if _log_task:
        await _log_queue.put(None)
        await _log_task
        _log_task = None

def log(message):
    """Enqueue a message to be logged."""
    if not IS_DEBUG:
        return
    try:
        _log_queue.put_nowait(message)
    except Exception:
        pass

def log_exception():
    """Enqueue the current exception traceback to be logged."""
    exc_type, exc_value, exc_tb = sys.exc_info()
    try:
        if exc_tb:
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            lineno = exc_tb.tb_lineno
        else:
            fname = "unknown"
            lineno = 0
        exc_text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        log("> {0}, line {1} = {2}".format(fname, lineno, exc_text))
    except Exception:
        pass

class Log(object):
    @staticmethod
    def log_p2p(message, node_id=""):
        if not IS_DEBUG:
            return
        out = "p2p: <{0}> {1}".format(node_id, message)
        log(out)
