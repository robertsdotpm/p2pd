import asyncio
from contextlib import suppress
from aionetiface import *
from ..errors import AlreadyClosedError


async def close_helper(p):
    # type: (Any) -> None
    try:
        await p.close()
    except AlreadyClosedError:
        pass
    except (OSError, asyncio.TimeoutError):
        log_exception()
        log("Error closing " + str(p))


async def close_with_timeout(p):
    # type: (Any) -> None
    try:
        await asyncio.wait_for(close_helper(p), timeout=2)
    except asyncio.TimeoutError:
        log("Timeout closing " + str(p) + " endpoint t = " + str(p.endpoint_type))


# Shutdown the node server and do cleanup.
async def node_stop(node):
    # type: (Any) -> None
    # Send stop signal (any amount of data.)
    try:
        node.stop_writer.send(b"Meow")
    except OSError:
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
                except BaseException:
                    # Plugin future completed with an exception; nothing to close.
                    continue
                if hasattr(pipe, "close"):
                    try:
                        await close_with_timeout(pipe)
                    except (OSError, asyncio.TimeoutError):
                        pass

    if getattr(node, "resources", None):
        await node.resources.close()

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
    for sock in (
        getattr(node, "stop_reader", None),
        getattr(node, "stop_writer", None),
    ):
        if sock is not None:
            with suppress(Exception):
                sock.close()
    node.stop_reader = None
    node.stop_writer = None

    log("stop node () ending")
