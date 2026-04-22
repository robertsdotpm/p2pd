"""Resource lifecycle management for a p2pd node."""
from typing import Any
import asyncio
from aionetiface import log_exception, cancel_tasks


class NodeResources:
    """Owns all background tasks and closeable factories for a node.

    Anything that needs cleanup on shutdown registers here.
    node_stop calls close() once and everything is torn down in order.
    """

    def __init__(self) -> None:
        self.closeables = []
        self.tasks = []
        self.idle_pipe_closer = None
        self.punch_factory = None
        self.last_recv_table = {}  # pipe.sock -> time
        self.last_recv_queue = []  # FIFO pipe refs for idle tracking

    def register(self, closeable: Any) -> None:
        """Add a closeable object to be shut down when the node stops."""
        self.closeables.append(closeable)

    def add_task(self, task: Any) -> None:
        """Track a background asyncio task so it can be cancelled on shutdown."""
        self.tasks.append(task)

    def set_idle_closer(self, task: Any) -> None:
        """Store the idle-pipe-closer task so it can be cancelled during shutdown."""
        self.idle_pipe_closer = task

    async def close(self) -> None:
        """Cancel all tracked tasks and close all registered closeables in order."""
        if self.idle_pipe_closer is not None:
            await cancel_tasks([self.idle_pipe_closer])
            self.idle_pipe_closer = None

        if self.tasks:
            await cancel_tasks(self.tasks)
            self.tasks.clear()

        for closeable in self.closeables:
            try:
                await closeable.close()
            except (OSError, asyncio.TimeoutError):
                log_exception()
