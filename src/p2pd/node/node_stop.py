"""Graceful shutdown logic for a p2pd node."""
from typing import Any
import asyncio
import glob
import os
from contextlib import suppress
from aionetiface import log, log_exception, Daemon
from ..errors import AlreadyClosedError


def cleanup_stale_pidfiles(install_path: str) -> None:
    """Delete *_pid.txt files in install_path whose locks aren't held.

    The daemon writes one pidfile per (af, proto, port, ip) listener
    and uses InterProcessLock to detect zombie servers on restart.
    On a clean shutdown the lock is released but the file persists,
    accumulating stale entries over many runs.  This sweep tries to
    reacquire each lock non-blockingly: success means no live process
    holds it, so the file is safe to remove; failure means another
    p2pd instance still owns it and we leave it alone.
    """
    try:
        from aionetiface.vendor.fasteners import InterProcessLock
    except ImportError:
        return

    try:
        candidates = glob.glob(os.path.join(install_path, "*_pid.txt"))
    except OSError:
        log_exception()
        return

    for path in candidates:
        try:
            lock = InterProcessLock(path)
            if lock.acquire(blocking=False):
                try:
                    lock.release()
                except OSError:
                    log_exception()
                try:
                    os.unlink(path)
                except OSError:
                    log_exception()
        except OSError:
            log_exception()


async def close_helper(p: Any) -> None:
    """Call p.close(), silently swallowing AlreadyClosedError and logging other exceptions."""
    try:
        await p.close()
    except AlreadyClosedError:
        pass
    except (OSError, asyncio.TimeoutError):
        log_exception()
        log("Error closing " + str(p))


async def close_with_timeout(p: Any) -> None:
    """Close p with a 2-second timeout, logging a warning if the close operation hangs."""
    try:
        await asyncio.wait_for(close_helper(p), timeout=2)
    except asyncio.TimeoutError:
        log("Timeout closing " + str(p) + " endpoint t = " + str(p.endpoint_type))


# Shutdown the node server and do cleanup.
async def node_stop(node: Any) -> None:
    """Shut down the node, closing traversal plugins, resources, the daemon, and the stop socket pair."""
    # Send stop signal (any amount of data.)
    try:
        node.stop_writer.send(b"Meow")
    except OSError:
        pass

    # Stop error logging thread.
    log(None)

    # Close all pipes stored in plugins.
    traversal_plugins = (
        node.traversal.plugins
        if getattr(node, "traversal", None) is not None
        else {}
    )
    for pipe_id in traversal_plugins:
        plugin = traversal_plugins[pipe_id]
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

    # Close the MQTT router and its background dispatcher tasks. Without this,
    # dispatcher coroutines from each MQTTClient stay pending after node_stop
    # and hang the test runner's final asyncio.gather on cancelled tasks.
    router = getattr(node, "router", None)
    if router is not None and hasattr(router, "close"):
        try:
            await asyncio.wait_for(router.close(), timeout=4)
        except asyncio.TimeoutError:
            log("Timeout closing node.router")

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

    install_path = getattr(node, "install_path", None)
    if install_path:
        cleanup_stale_pidfiles(install_path)

    log("stop node () ending")
