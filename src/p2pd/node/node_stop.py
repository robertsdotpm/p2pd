import asyncio
import sys
import multiprocessing
from aionetiface import *
from ..errors import AlreadyClosedError


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

async def shutdown_executor_with_timeout(executor, timeout=3):
    loop = asyncio.get_running_loop()
    # Run shutdown in a separate thread
    shutdown_future = loop.run_in_executor(None, executor.shutdown, True)
    
    try:
        await asyncio.wait_for(shutdown_future, timeout=timeout)
    except asyncio.TimeoutError:
        # Still blocking after timeout
        log("Warning: executor shutdown timed out")

# Shutdown the node server and do cleanup.
async def node_stop(node):
    # Send stop signal (any amount of data.)
    node.stop_writer.send(b"Meow")

    # Stop error logging thread.
    log(None)

    # Close all pipes stored in plugins.
    for pipe_id in node.traversal.plugins:
        plugin = node.traversal.plugins[pipe_id]
        result = plugin.result
        if isinstance(result, asyncio.Future):
            if result.done():
                pipe = result.result()
                if hasattr(pipe, "close"):
                    try:
                        await pipe.close()
                    except Exception:
                        pass

    # Close other pipes.
    pipe_lists = [
        node.signal_pipes,
        node.turn_clients,
        #node.pipes,
    ]

    # For all active pipes, attempt to close them.
    # Skip if already closed if not resolved to a pipe.
    tasks = []
    for pipe_list in pipe_lists:
        for pipe in pipe_list.values():
            if pipe is None:
                continue

            if isinstance(pipe, asyncio.Future):
                if pipe.done():
                    pipe = pipe.result()
                else:
                    continue

            tasks.append(close_with_timeout(pipe))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    # Stop node server.
    await super(node.__class__, node).close()

    # Try close the multiprocess manager.
    if node.pp_executor:
        """
        Process pool executor is not that great at shut down.
        At least prevent it from hanging forever by using a thread
        with a 3 second upper bound on shutdown blocking.
        """
        log("trying to shut down pp executor waiting.")

        """
        Attempts a clean shutdown, but forces termination after 'timeout' seconds.
        """
        # Trigger the standard shutdown
        if sys.version_info >= (3, 9):
            node.pp_executor.shutdown(wait=True, cancel_futures=True)
        else:
            node.pp_executor.shutdown(wait=True)

        # Timeout reached: forceful shutdown.
        for child in multiprocessing.active_children():
            # This sends SIGTERM on Linux and TerminateProcess on Windows
            child.terminate()
            
        # Final check to ensure they are cleaned up
        for child in multiprocessing.active_children():
            child.join(timeout=0.5)

        #await shutdown_executor_with_timeout(node.pp_executor)
        log("shutdown for pp executor done.")

    log("stop node () ending")
