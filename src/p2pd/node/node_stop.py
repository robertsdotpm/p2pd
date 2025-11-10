import asyncio
from ..errors import *
from ..utility.utils import *

# Shutdown the node server and do cleanup.
async def node_stop(node):
    # Make the worker thread for punching end.
    node.punch_queue.put_nowait(None)
    if node.punch_worker_task is not None:
        node.punch_worker_task.cancel()
        node.punch_worker_task = None

    # Stop sig message dispatcher.
    node.sig_msg_queue.put_nowait(None)
    if node.sig_msg_queue_worker_task is not None:
        node.sig_msg_queue_worker_task.cancel()
        node.sig_msg_queue_worker_task = None

    # Close other pipes.
    pipe_lists = [
        node.signal_pipes,
        node.tcp_punch_clients,
        node.turn_clients,
        node.pipes,
    ]

    # For all active pipes, attempt to close them.
    # Skip if already closed if not resolved to a pipe.
    for pipe_list in pipe_lists:
        for pipe in pipe_list.values():
            if pipe is None:
                continue

            if isinstance(pipe, asyncio.Future):
                if pipe.done():
                    pipe = pipe.result()
                else:
                    continue
            
            """
            Pipes can be closed manually by programs that clean up after themselves
            or if a TCP pipe ends up having the other side hang up cleanly and
            the connection ends. In this case, alreadyclosed isn't unexpected.
            """
            try:
                await pipe.close()
            except AlreadyClosedError:
                continue

    # Try close the multiprocess manager.
    """
    Node close will throw: 
    Exception ignored in: <function BaseEventLoop.__del__
    with socket error -1

    So you need to make sure to wrap coroutines for exceptions.
    """
    if node.pp_executor:
        log("trying to shut down pp executor waiting.")
        node.pp_executor.shutdown(wait=True)
        log("shutdown for pp executor done.")

    # Stop node server.
    await super(node.__class__, node).close()