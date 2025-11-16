import asyncio
from ..errors import AlreadyClosedError
from ..utility.utils import *
from .node_defs import *
from ..net.asyncio.async_run import *

async def close_helper(p):
    try:
        await p.close()
    except AlreadyClosedError:
        pass
    except Exception as e:
        log_exception()
        log("Error closing " + str(p))

async def close_with_timeout(p):
    try:
        await asyncio.wait_for(
            close_helper(p), 
            timeout=2
        )
    except asyncio.TimeoutError:
        log("Timeout closing " + str(p) + " endpoint t = " + str(p.endpoint_type))

# Shutdown the node server and do cleanup.
async def node_stop(node):
    log("node stop 1")

    # Set the shutdown event if it's not set.
    if not shutdown_event.is_set():
        shutdown_event.set()

    log("node stop 2")

    # Make the worker thread for punching end.
    node.punch_queue.put_nowait(None)
    if node.punch_worker_task is not None:
        node.punch_worker_task.cancel()
        node.punch_worker_task = None

    log("node stop 3")

    # Stop sig message dispatcher.
    node.sig_msg_queue.put_nowait(None)
    if node.sig_msg_queue_worker_task is not None:
        node.sig_msg_queue_worker_task.cancel()
        node.sig_msg_queue_worker_task = None

    log("node stop 4")

    # Close other pipes.
    pipe_lists = [
        node.signal_pipes,
        node.tcp_punch_clients,
        node.turn_clients,
        node.pipes,
    ]

    log("node stop 5")

    # For all active pipes, attempt to close them.
    # Skip if already closed if not resolved to a pipe.
    tasks = []
    loop = asyncio.get_event_loop()
    for pipe_list in pipe_lists:
        for pipe in pipe_list.values():
            if pipe is None:
                continue

        if not isinstance(pipe, asyncio.Future):
            continue

        if not pipe.done():
            continue

        try:
            if pipe.done():
                pipe = pipe.result()
                tasks.append(close_with_timeout(pipe))
        except Exception as e:
            # handle other exceptions from the Future
            log_exception(e)
            continue

    log("node stop 6")

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    log("node stop 7")

    # Try close the multiprocess manager.
    """
    Node close will throw: 
    Exception ignored in: <function BaseEventLoop.__del__
    with socket error -1

    So you need to make sure to wrap coroutines for exceptions.
    """
    if node.pp_executor:
        log("trying to shut down pp executor waiting.")

        await loop.run_in_executor(None, node.pp_executor.shutdown, True)
        #node.pp_executor.shutdown(wait=True)
        log("shutdown for pp executor done.")

    log("stop node () ending")

    # Stop node server.
    await super(node.__class__, node).close()