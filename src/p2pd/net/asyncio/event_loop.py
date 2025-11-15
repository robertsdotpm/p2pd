"""
In Python3 with asyncio, the "correct" way to close a protocol transport
is to call close on the transport. You can also await an event set in
connection_lost. You would think that would be enough to indicate that
the underlying socket was closed (but it's not.)

At some nebulous point later: the event loop still has to close the socket
and delete it from being monitored. The advice to make sure this happens
is to await asyncio.sleep(0) to ensure the event loop runs to process
the transport.close() properly. But ah... wait, no, that also doesn't
work. The issue is you have no control on what happens when an
event loop runs / what it prioritized / which is a race condition.
That's the whole thing with coroutines and concurrency -- ordering
is unpredictable. So the whole await sleep ... pattern is non-sense.

This is also the reason why almost all Python network code in the wild
is wrong and littered with resource bugs about unclosed sockets.
So how to properly solve the issue? Just my view, but I think the right
way is to make the event loop set an event when a socket is closed. Then
you can get the awaitable and await when the event loop closes it. 

Some caveats in implementing this though: a first attempt might try to
overload internal reader / writer close functions. But the thing with
internal APIs is they can change between Python versions. For 3.13 APIs
like _remove_reader didn't exist in Python 3.5 (and this project is going
for heavy backwards compatibility.) So the approach I take is this: go
one level deeper -- and create a custom Selector. Then it's possible to
--only-- use public APIs to signal socket close behavior: unregister
and modify (available since Python 3.4.)

BTW: this is for asyncio.SelectorEventLoop only. There are other event loops,
this project only uses Selector though as its the one that works with
complex code like TCP hole punching.
"""

import asyncio
import socket
import selectors
import traceback
from ...utility.utils import *

# Map: FD -> Future object
_CLOSE_FUTURES = {}

class ProxySelector:
    """A wrapper around the actual selector object to intercept unregister calls."""
    
    def __init__(self, selector_instance, loop):
        self._selector = selector_instance
        self._loop = loop
        self.select = selector_instance.select
        self.close = selector_instance.close
        self.register = selector_instance.register
        self.get_map = selector_instance.get_map
        self.get_key = selector_instance.get_key

    def _maybe_signal_removal(self, fd: int, events: int, data: tuple) -> None:
        """Helper to signal the future if the FD is being completely unregistered."""
        
        # Check if the FD's future exists
        if fd not in _CLOSE_FUTURES:
            #_CLOSE_FUTURES[fd] = self._loop.create_future()
            return

        # In the context of a fully-removed item:
        if events == 0 and data is None:
            future = _CLOSE_FUTURES.pop(fd)
            if not future.done():
                self._loop.call_soon(future.set_result, True)

    def unregister(self, fd):
        """Intercepts the complete removal of the FD."""
        # The FD is being completely removed. Signal the removal future.
        self._maybe_signal_removal(fd, 0, None)
        return self._selector.unregister(fd)
    
    def modify(self, fd, events, data=None):
        """Intercepts modification, checking if FD is effectively unregistered."""
        if events == 0:
            # FD modified to watch for 0 events, it's equivalent to unregister.
            self._maybe_signal_removal(fd, 0, None)
        elif events != 0:
            # NOTE: This is tricky, the SelectorEventLoop mostly handles this.
            # We focus on the unregister/events=0 case for reliability.
            pass

        return self._selector.modify(fd, events, data)

class CustomEventLoop(asyncio.SelectorEventLoop):
    """Event loop that uses the ProxySelector."""
    
    def __init__(self, selector=None):
        # Determine the default selector class if none is provided
        if selector is None:
            selector_cls = selectors.DefaultSelector
            # Create an instance of the *real* selector
            real_selector = selector_cls()
        else:
            # Assume 'selector' is the actual selector instance
            real_selector = selector
            
        # 1. Wrap the real selector with our proxy
        proxy_selector = ProxySelector(real_selector, self)
        
        # 2. Initialize the base class with our proxy
        # The base SelectorEventLoop expects a selector object here.
        super().__init__(proxy_selector)
        
    # Add your public API method back (using the global map from the proxy)
    def await_fd_close(self, sock: socket) -> asyncio.Future:
        fd = sock.fileno()
        if fd == -1:
            log("-1 passed to await_fd_close()!")
            f = self.create_future()
            f.set_result(True)
            return f

        if fd not in _CLOSE_FUTURES:
            _CLOSE_FUTURES[fd] = self.create_future()
            
        return _CLOSE_FUTURES[fd]

class CustomEventLoopPolicy(asyncio.DefaultEventLoopPolicy):
    @staticmethod
    def exception_handler(self, context):
        """
        Custom asyncio exception handler.
        Logs exception type, message, and the line number where it occurred.
        Compatible with Python 3.5+.
        """
        buf = []

        buf.append("Exception handler in custom event loop")
        exc = context.get("exception")
        if exc is None:
            # No exception object, log the message
            msg = context.get("message", "Unknown exception")
            buf.append("No exception object, context message: " + str(msg))
            log("\n".join(buf))
            return

        # Log the exception type and message
        buf.append("Exception type: " + str(type(exc).__name__))
        buf.append("Exception message: " + str(exc))

        # Extract traceback and log the last frame (where exception occurred)
        tb = exc.__traceback__
        if tb is not None:
            while tb.tb_next:
                tb = tb.tb_next
            frame = tb.tb_frame
            lineno = tb.tb_lineno
            filename = frame.f_code.co_filename
            funcname = frame.f_code.co_name
            buf.append("Occurred in " + filename + ", function " + funcname + ", line " + str(lineno))

        # Log full traceback
        buf.append("Full traceback:")
        buf.append("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))

        # Write all at once
        log("\n".join(buf))

    @staticmethod
    def loop_setup(loop):
        loop.set_debug(False)
        loop.set_exception_handler(CustomEventLoopPolicy.exception_handler)
        loop.default_exception_handler = CustomEventLoopPolicy.exception_handler

    def new_event_loop(self):
        selector = selectors.SelectSelector()
        loop = CustomEventLoop(selector)
        CustomEventLoopPolicy.loop_setup(loop)
        return loop