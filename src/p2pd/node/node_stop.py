import asyncio
import os
import signal
import sys
import multiprocessing
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

    # Close other pipes.
    pipe_lists = [
        node.signal_pipes,
        node.turn_clients,
        #node.pipes,
    ]

    # For all active pipes, attempt to close them.
    # Skip if already closed or not resolved to a pipe.
    tasks = []
    for pipe_list in pipe_lists:
        for pipe in pipe_list.values():
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

    # Try close the multiprocess manager.
    if node.pp_executor:
        """
        ProcessPoolExecutor does not shut down cleanly on its own.
        Strategy: ask it to stop, poll for its specific worker processes
        to exit (up to 3 s), then force-terminate any stragglers.
        On Unix we escalate SIGTERM → SIGKILL so signal-ignoring workers
        cannot hang the shutdown.  On Windows terminate() already calls
        TerminateProcess() which is a hard kill.
        """
        log("trying to shut down pp executor waiting.")

        # Snapshot the executor's own worker PIDs *before* calling shutdown()
        # so we only touch those processes and not unrelated children.
        # _processes is a CPython implementation detail (dict pid→Process);
        # fall back to affecting all active children if it is missing.
        executor_pids = set()
        try:
            executor_pids = set(node.pp_executor._processes.keys())
        except AttributeError:
            pass

        # 1. Trigger the standard shutdown (non-blocking).
        if sys.version_info >= (3, 9):
            node.pp_executor.shutdown(wait=False, cancel_futures=True)
        else:
            node.pp_executor.shutdown(wait=False)

        # Clear immediately so a second call to node_stop() cannot re-enter.
        node.pp_executor = None

        # 2. Poll until the executor's workers exit or the 3-second deadline passes.
        loop = asyncio.get_running_loop()
        end = loop.time() + 3
        while True:
            active = multiprocessing.active_children()
            if executor_pids:
                remaining = {c for c in active if c.pid in executor_pids}
            else:
                remaining = set(active)
            if not remaining or loop.time() >= end:
                break
            await asyncio.sleep(0.5)

        # 3. Force-terminate only this executor's workers that are still alive.
        active = multiprocessing.active_children()
        targets = [c for c in active if not executor_pids or c.pid in executor_pids]
        for child in targets:
            # SIGTERM on Linux/macOS; TerminateProcess() on Windows.
            child.terminate()

        # 4. On Unix, escalate to SIGKILL for processes that ignore SIGTERM.
        if sys.platform != "win32" and targets:
            await asyncio.sleep(0.2)
            active_pids = {c.pid for c in multiprocessing.active_children()}
            for child in targets:
                if child.pid in active_pids:
                    try:
                        os.kill(child.pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass  # Already exited or cannot kill.

        # 5. Final reap.
        for child in targets:
            child.join(timeout=0.5)

        log("shutdown for pp executor done.")

    log("stop node () ending")
