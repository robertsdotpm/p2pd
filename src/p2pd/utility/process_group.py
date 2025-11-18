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

def check_worker(q):
    q.put("ok")

def check_multiprocessing_available(timeout=1.0):
    out_q = mp.Queue()
    p = mp.Process(target=check_worker, args=(out_q,))
    p.start()

    try:
        result = out_q.get(timeout=timeout)  # <-- get before join
    except Exception:
        p.terminate()
        raise RuntimeError("Queue failed to return data")

    p.join(timeout=timeout)
    if p.is_alive():
        p.terminate()
        raise RuntimeError("Process did not exit in time")

    if result != "ok":
        raise RuntimeError("Queue returned unexpected data: {}".format(result))

    return True

import multiprocessing as mp
import threading
import uuid
import traceback
from queue import Queue, Empty
from concurrent.futures import Future
import time


def job_wrapper(func, args, kwargs, completed_queue, job_id):
    """Wrapper executed in a separate process."""
    try:
        result = func(*args, **kwargs)
        completed_queue.put((job_id, True, result))
    except Exception as e:
        tb = traceback.format_exc()
        completed_queue.put((job_id, False, (repr(e), tb)))


class ProcessManager:
    """Lock-free, one-process-per-job manager with futures."""

    def __init__(self, queue_timeout=0.5):
        self.job_queue = Queue()       # Holds (job_id, future, process)
        self.completed_queue = mp.Queue()  # Holds (job_id, ok, data)
        self.stopping = False
        self.queue_timeout = queue_timeout
        self.listener_thread = threading.Thread(target=self.listener, daemon=True)
        self.listener_thread.start()

    def submit(self, func, *args, **kwargs):
        """Submit a job and immediately return a Future."""
        if self.stopping:
            raise RuntimeError("ProcessManager stopping")

        job_id = uuid.uuid4().hex
        fut = Future()
        p = mp.Process(
            target=job_wrapper,
            args=(func, args, kwargs, self.completed_queue, job_id)
        )
        p.start()
        self.job_queue.put((job_id, fut, p))
        return fut

    def listener(self):
        """Thread that waits for completed jobs and sets futures."""
        while not self.stopping or not self.job_queue.empty():
            try:
                job_id, ok, data = self.completed_queue.get(timeout=self.queue_timeout)
            except Empty:
                continue  # Check stopping flag

            # Find the matching job in job_queue
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
                continue  # Shouldn't happen, but safe

            _, fut, p = found_item

            # Ensure process has exited
            if p.is_alive():
                p.join(timeout=1)
                if p.is_alive():
                    p.terminate()

            # Set result/exception
            if ok:
                fut.set_result(data)
            else:
                msg, tb = data
                fut.set_exception(RuntimeError(f"Worker exception: {msg}\n{tb}"))

    def shutdown(self):
        """Terminate all active processes and stop the listener."""
        self.stopping = True
        # Terminate active processes
        while not self.job_queue.empty():
            _, fut, p = self.job_queue.get()
            if p.is_alive():
                p.terminate()
            if not fut.done():
                fut.set_exception(RuntimeError("ProcessManager shutting down"))
        # Wait for listener to exit
        self.listener_thread.join(timeout=2)

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