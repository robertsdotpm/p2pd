"""Command-line entry point and interactive REPL for p2pd."""
from typing import Any
import ast
import asyncio
import code
import concurrent.futures
import inspect
import sys
import threading
import types
import warnings
import multiprocessing
import platform



vmaj, vmin, _ = platform.python_version_tuple()
if int(vmin) < 8:
    print("P2PD REPL needs >= Python 3.8")
    exit()

from . import __version__ as p2pdv  # noqa: E402
from aionetiface import *  # noqa: E402


class AsyncIOInteractiveConsole(code.InteractiveConsole):
    """Interactive Python console that supports top-level await via asyncio."""

    def __init__(self, locals: Any, loop: Any) -> None:
        super().__init__(locals)
        self.compile.compiler.flags |= ast.PyCF_ALLOW_TOP_LEVEL_AWAIT

        self.loop = loop
        # Tracks the running REPL task (if any) and whether the user hit
        # Ctrl-C while it was executing. Kept as instance state rather than
        # globals so the console's lifetime bounds them.
        self.repl_future = None
        self.repl_future_interrupted = False

    def runcode(self, code: Any) -> None:
        """Execute a code object in the asyncio event loop, supporting top-level await."""
        future = concurrent.futures.Future()

        def callback() -> None:
            """Schedule the coroutine from the compiled code on the asyncio loop."""
            self.repl_future = None
            self.repl_future_interrupted = False

            func = types.FunctionType(code, self.locals)
            try:
                coro = func()
            except SystemExit:
                raise
            except KeyboardInterrupt as ex:
                self.repl_future_interrupted = True
                future.set_exception(ex)
                return
            except BaseException as ex:
                future.set_exception(ex)
                return

            if not inspect.iscoroutine(coro):
                future.set_result(coro)
                return

            try:
                self.repl_future = self.loop.create_task(coro)

                def propagate(task: Any) -> None:
                    """Mirror the task's outcome onto the console's futures-Future result."""
                    if task.cancelled():
                        future.cancel()
                    elif task.exception() is not None:
                        future.set_exception(task.exception())
                    else:
                        future.set_result(task.result())

                self.repl_future.add_done_callback(propagate)
            except BaseException as exc:
                future.set_exception(exc)

        self.loop.call_soon_threadsafe(callback)

        try:
            return future.result()
        except SystemExit:
            raise
        except BaseException:
            if self.repl_future_interrupted:
                self.write("\nKeyboardInterrupt\n")
            else:
                self.showtraceback()


class REPLThread(threading.Thread):
    """Background thread that drives the asyncio REPL console interaction."""

    def run(self) -> None:
        """Drive the interactive REPL console until the user exits."""
        try:
            loop_policy = str(asyncio.get_event_loop_policy())
            if "elector" in loop_policy:
                loop_policy = "selector"

            spawn_method = multiprocessing.get_start_method()
            vmaj, vmin, _ = platform.python_version_tuple()
            banner = (
                fstr(
                    "P2PD {0} REPL on Python {1}.{2} / {3}",
                    (
                        p2pdv,
                        vmaj,
                        vmin,
                        sys.platform,
                    ),
                ),
                fstr(
                    "Loop = {0}, Process = {1}",
                    (
                        loop_policy,
                        spawn_method,
                    ),
                ),
                'Use "await" directly instead of "asyncio.run()".',
                fstr("{0}from p2pd import *", (getattr(sys, "ps1", ">>> "),)),
            )

            console.push("from p2pd.do_imports import *")
            console.interact(
                banner="\n".join(banner), exitmsg="exiting asyncio REPL..."
            )

        finally:
            warnings.filterwarnings(
                "ignore",
                message=r"^coroutine .* was never awaited$",
                category=RuntimeWarning,
            )

            loop.call_soon_threadsafe(loop.stop)


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    repl_locals = {"asyncio": asyncio}
    for key in {
        "__name__",
        "__package__",
        "__loader__",
        "__spec__",
        "__builtins__",
        "__file__",
    }:
        repl_locals[key] = locals()[key]

    console = AsyncIOInteractiveConsole(repl_locals, loop)

    try:
        import readline  # NoQA
    except ImportError:
        pass

    repl_thread = REPLThread()
    repl_thread.daemon = True
    repl_thread.start()

    while True:
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            if console.repl_future and not console.repl_future.done():
                console.repl_future.cancel()
                console.repl_future_interrupted = True
            continue
        else:
            break

    # ---- Clean shutdown ----
    # Cancel every pending task so sockets / transports are closed properly
    # and Python doesn't emit "Task was destroyed but it is pending!" or
    # "unclosed socket" ResourceWarnings.
    try:
        pending = asyncio.all_tasks(loop)
    except AttributeError:
        # Python 3.6
        pending = asyncio.Task.all_tasks(loop)

    for task in pending:
        task.cancel()

    if pending:
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))

    try:
        if hasattr(loop, "shutdown_asyncgens"):
            loop.run_until_complete(loop.shutdown_asyncgens())
        if hasattr(loop, "shutdown_default_executor"):
            loop.run_until_complete(loop.shutdown_default_executor())
    finally:
        loop.close()
