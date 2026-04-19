import asyncio
from aionetiface import *


class NodeResources:
    """Owns all background tasks and closeable factories for a node.

    Anything that needs cleanup on shutdown registers here.
    node_stop calls close() once and everything is torn down in order.
    """

    def __init__(self):
        self.closeables = []
        self.tasks = []
        self.idle_pipe_closer = None
        self.punch_factory = None
        self.last_recv_table = {}  # pipe.sock -> time
        self.last_recv_queue = []  # FIFO pipe refs for idle tracking

    def register(self, closeable):
        self.closeables.append(closeable)

    def add_task(self, task):
        self.tasks.append(task)

    def set_idle_closer(self, task):
        self.idle_pipe_closer = task

    async def close(self):
        if self.idle_pipe_closer is not None:
            await cancel_tasks([self.idle_pipe_closer])
            self.idle_pipe_closer = None

        if self.tasks:
            await cancel_tasks(self.tasks)
            self.tasks.clear()

        for closeable in self.closeables:
            try:
                await closeable.close()
            except Exception:
                log_exception()
