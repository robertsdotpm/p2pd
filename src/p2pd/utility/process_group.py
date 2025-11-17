"""
TCP hole punching code is notoriously timing-sensitive.
On Python because of the GIL: there is one OS thread.
When you run an event loop and a Python thread, your punching code
get interrupted and as a result success rates drop compared to
using processes. But there are caveats with processes, too.

My previous code used "ProcessPoolExecutors" to run the punching
stuff. For cross-process communication: they started a service and
passed messages between them to the main thread. But ProcessPoolExec
are apparently not meant for long-running use. A huge downside of
this approach was shut down could occasionally lead to dead locks.

This is based on more standard multiprocessing stuff but still
uses backported async_run funcs to start event loops and such.
"""

import multiprocessing as mp
import threading
import uuid
import traceback
from concurrent.futures import Future
from queue import Queue, Empty

def check_multiprocessing_available(timeout=1.0):
    """Check if Process and Queue work on this platform."""
    try:
        out_q = mp.Queue()
        
        def worker(q):
            q.put("ok")

        p = mp.Process(target=worker, args=(out_q,))
        p.start()
        p.join(timeout=timeout)

        if p.is_alive():
            p.terminate()
            raise RuntimeError("Process did not exit in time")

        try:
            result = out_q.get(timeout=timeout)
        except Exception:
            raise RuntimeError("Queue failed to return data")

        if result != "ok":
            raise RuntimeError("Queue returned unexpected data: {}".format(result))

    except Exception as e:
        tb = traceback.format_exc()
        raise RuntimeError("Multiprocessing not available: {} \n{}".format(e, tb))

    return True

def job_wrapper(func, args, kwargs, out_q, job_id):
    """Wrapper executed in a separate process."""
    try:
        result = func(*args, **kwargs)
        out_q.put((job_id, True, result))
    except Exception as e:
        tb = traceback.format_exc()
        out_q.put((job_id, False, (repr(e), tb)))


class ProcessManager:
    """Manages one-process-per-job execution with futures (lock-free)."""

    def __init__(self):
        self.out_q = mp.Queue()
        self.job_queue = Queue()  # queue of (job_id, future, process)
        self.stopping = False
        self.listener_thread = threading.Thread(target=self.listener, daemon=True)
        self.listener_thread.start()

    def submit(self, func, *args, **kwargs):
        """Submit a job, returns a Future immediately."""
        if self.stopping:
            raise RuntimeError("ProcessManager stopping")

        job_id = uuid.uuid4().hex
        fut = Future()
        p = mp.Process(
            target=job_wrapper, 
            args=(func, args, kwargs, self.out_q, job_id)
        )

        p.start()

        # Thread-safe queue; no explicit lock needed
        self.job_queue.put((job_id, fut, p))

        return fut

    def listener(self):
        """Thread that waits for results and sets futures."""
        while not self.stopping:
            try:
                job_id, ok, data = self.out_q.get(timeout=0.1)
            except Empty:
                continue

            # Scan the queue to find the matching future/process
            found_item = None
            temp_queue = Queue()
            while not self.job_queue.empty():
                item = self.job_queue.get()
                if item[0] == job_id:
                    found_item = item
                else:
                    temp_queue.put(item)

            self.job_queue = temp_queue
            if not found_item:
                continue

            _, fut, p = found_item
            if p.is_alive():
                p.join(timeout=1)
                if p.is_alive():
                    p.terminate()

            if ok:
                fut.set_result(data)
            else:
                msg, tb = data
                fut.set_exception(RuntimeError("Worker exception: " + msg + "\n" + tb))

    def shutdown(self):
        """Terminate all active processes and stop the listener."""
        self.stopping = True

        while not self.job_queue.empty():
            _, fut, p = self.job_queue.get()
            if p.is_alive():
                p.terminate()
            if not fut.done():
                fut.set_exception(RuntimeError("ProcessManager shutting down"))

def multiply(a, b):
    return a * b

def fail_func():
    raise ValueError("Something went wrong!")

if __name__ == "__main__":
    manager = ProcessManager()

    fut1 = manager.submit(multiply, 5, 6)
    fut2 = manager.submit(multiply, 7, 8)
    fut3 = manager.submit(fail_func)

    print(fut1.result())  # 30
    print(fut2.result())  # 56

    try:
        fut3.result()
    except RuntimeError as e:
        print("Caught expected exception:")
        print(e)

    manager.shutdown()