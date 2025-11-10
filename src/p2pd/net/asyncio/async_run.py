import asyncio
from asyncio import events, coroutines, tasks

def patch_asyncio_backports(loop_cls=None):
    from concurrent.futures import ThreadPoolExecutor

    # Default to whatever class is passed, or fall back to the base event loop
    if loop_cls is None:
        loop_cls = asyncio.get_event_loop().__class__

    if not hasattr(loop_cls, "shutdown_asyncgens"):
        async def _noop(self): pass
        loop_cls.shutdown_asyncgens = _noop

    if not hasattr(loop_cls, "shutdown_default_executor"):
        async def _shutdown_default_executor(self):
            executor = getattr(self, "_default_executor", None)
            if executor is not None:
                executor.shutdown(wait=True)
        loop_cls.shutdown_default_executor = _shutdown_default_executor

import asyncio

def _cancel_all_tasks(loop):
    # Try to get all tasks in a version- and implementation-safe way
    try:
        # Python 3.7+
        to_cancel = asyncio.all_tasks(loop)
    except AttributeError:
        # Python 3.4–3.6: Task.all_tasks() may be on either asyncio.Task or _asyncio.Task
        Task = getattr(asyncio, "Task", None)
        if Task is None or not hasattr(Task, "all_tasks"):
            # fall back to the pure-Python module if C version is missing the method
            import types
            for name, mod in list(asyncio.__dict__.items()):
                if isinstance(mod, types.ModuleType) and hasattr(mod, "Task"):
                    Task = mod.Task
                    break
        to_cancel = Task.all_tasks(loop) if Task else set()

    if not to_cancel:
        return

    for task in to_cancel:
        task.cancel()

    loop.run_until_complete(asyncio.gather(*to_cancel, return_exceptions=True))
    for task in to_cancel:
        if task.cancelled():
            continue
        try:
            exc = task.exception()
        except asyncio.CancelledError:
            continue
        if exc is not None:
            loop.call_exception_handler({
                'message': 'unhandled exception during asyncio.run() shutdown',
                'exception': exc,
                'task': task,
            })

def async_run(main, *, debug=False):
    """Execute the coroutine and return the result.

    This function runs the passed coroutine, taking care of
    managing the asyncio event loop and finalizing asynchronous
    generators.

    This function cannot be called when another asyncio event loop is
    running in the same thread.

    If debug is True, the event loop will be run in debug mode.

    This function always creates a new event loop and closes it at the end.
    It should be used as a main entry point for asyncio programs, and should
    ideally only be called once.
    """
    if events._get_running_loop() is not None:
        raise RuntimeError(
            "asyncio.run() cannot be called from a running event loop")

    if not coroutines.iscoroutine(main):
        raise ValueError("a coroutine was expected, got {!r}".format(main))

    loop = events.new_event_loop()
    try:
        events.set_event_loop(loop)
        loop.set_debug(debug)
        return loop.run_until_complete(main)
    finally:
        try:
            _cancel_all_tasks(loop)
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.run_until_complete(loop.shutdown_default_executor())
        finally:
            events.set_event_loop(None)
            loop.close()