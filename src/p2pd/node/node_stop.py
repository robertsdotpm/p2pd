import asyncio
from contextlib import suppress
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

async def _cancel_tasks(tasks):
    """Cancel a list of asyncio tasks and wait for them to finish."""
    live = [t for t in tasks if not t.done()]
    for t in live:
        t.cancel()
    if live:
        await asyncio.gather(*live, return_exceptions=True)


# Shutdown the node server and do cleanup.
async def node_stop(node):
    # Send stop signal (any amount of data.)
    try:
        node.stop_writer.send(b"Meow")
    except Exception:
        pass

    # Stop error logging thread.
    log(None)

    # Close all pipes stored in plugins.
    for pipe_id in node.traversal.plugins:
        plugin = node.traversal.plugins[pipe_id]
        result = plugin.result
        if isinstance(result, asyncio.Future):
            if result.cancelled():
                continue

            if result.done():
                try:
                    pipe = result.result()
                except Exception:
                    # Plugin future completed with an exception; nothing to close.
                    continue
                if hasattr(pipe, "close"):
                    try:
                        await close_with_timeout(pipe)
                    except Exception:
                        pass

    # Close signal pipes (MQTT connections).
    tasks = []
    for pipe in node.signal_pipes.values():
        if pipe is None:
            continue
        if isinstance(pipe, asyncio.Future):
            if pipe.cancelled() or not pipe.done():
                continue
            try:
                pipe = pipe.result()
            except Exception:
                continue
        tasks.append(close_with_timeout(pipe))
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    # Close factories that own resources (TURN clients, punch executor, etc.).
    for closeable in getattr(node, "closeables", []):
        try:
            await closeable.close()
        except Exception:
            log_exception()

    # Cancel the idle-pipe-closer background task.
    closer = getattr(node, "idle_pipe_closer", None)
    if closer is not None:
        await _cancel_tasks([closer])
        node.idle_pipe_closer = None

    # Cancel any other long-running node tasks (nickname refresh, etc.)
    if getattr(node, "tasks", None):
        await _cancel_tasks(node.tasks)
        node.tasks.clear()

    # Close the traversal manager's background signal-handler tasks.
    traversal = getattr(node, "traversal", None)
    if traversal is not None and hasattr(traversal, "close"):
        await traversal.close()

    # Stop node server (Daemon.close closes all listener pipes).
    # Using Daemon.close(node) directly rather than super(node.__class__, node).close()
    # because the super() pattern breaks if Node is ever subclassed: super(SubClass, node)
    # would resolve to Node, calling node_stop() again and looping infinitely.
    await Daemon.close(node)

    # Close the stop-signal socket pair.
    for sock in (getattr(node, "stop_reader", None), getattr(node, "stop_writer", None)):
        if sock is not None:
            with suppress(Exception):
                sock.close()
    node.stop_reader = None
    node.stop_writer = None

    log("stop node () ending")
