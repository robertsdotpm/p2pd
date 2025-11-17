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
from queue import Empty


def job_runner(func, args, kwargs, out_q, job_id):
    """Wrapper executed in a separate process."""
    try:
        result = func(*args, **kwargs)
        out_q.put((job_id, True, result))
    except Exception as e:
        tb = traceback.format_exc()
        out_q.put((job_id, False, (repr(e), tb)))


class ProcessManager:
    """Manages one-process-per-job execution with futures."""

    def __init__(self):
        self.out_q = mp.Queue()
        self.futures = {}          # job_id -> Future
        self.processes = {}        # job_id -> Process
        self.stopping = False
        self.lock = threading.Lock()  # protect futures/processes dicts
        self.listener_thread = threading.Thread(target=self.listener, daemon=True)
        self.listener_thread.start()

    def submit(self, func, *args, **kwargs):
        """Submit a job, returns a Future immediately."""
        if self.stopping:
            raise RuntimeError("ProcessManager stopping")

        result_future = Future()
        job_id = uuid.uuid4().hex
        p = mp.Process(
            target=job_runner, 
            args=(func, args, kwargs, self.out_q, job_id)
        )
        p.start()

        with self.lock:
            self.futures[job_id] = result_future
            self.processes[job_id] = p

        return result_future

    def listener(self):
        """Thread that waits for results and sets futures."""
        while not self.stopping:
            try:
                job_id, ok, data = self.out_q.get(timeout=0.1)
            except Empty:
                continue

            with self.lock:
                fut = self.futures.pop(job_id, None)
                p = self.processes.pop(job_id, None)

            if p and p.is_alive():
                p.join(timeout=1)
                if p.is_alive():
                    p.terminate()

            if fut is None:
                continue

            if ok:
                fut.set_result(data)
            else:
                msg, tb = data
                fut.set_exception(RuntimeError("Worker exception: " + msg + "\n" + tb))

    def shutdown(self):
        """Terminate all active processes and stop the listener."""
        self.stopping = True
        with self.lock:
            for p in self.processes.values():
                if p.is_alive():
                    p.terminate()

            self.processes.clear()
            for fut in self.futures.values():
                if not fut.done():
                    fut.set_exception(RuntimeError("ProcessManager shutting down"))

            self.futures.clear()

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