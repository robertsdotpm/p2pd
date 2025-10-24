import asyncio
import socket # For type hinting
import selectors
from ..utility.utils import *

# Map: FD -> Future object
_CLOSE_FUTURES: dict[int, asyncio.Future] = {}


class _CustomEventLoop(asyncio.SelectorEventLoop):
    def await_fd_close(self, sock: socket.socket) -> asyncio.Future:
        """
        Creates or returns a Future that resolves when the socket's File Descriptor (FD) 
        is removed from the event loop's monitoring set.
        """
        fd = sock.fileno()
        if fd not in _CLOSE_FUTURES:
            # Create a new Future and store it
            _CLOSE_FUTURES[fd] = self.create_future()
        return _CLOSE_FUTURES[fd]
    
    def _signal_fd_removal(self, fd: int) -> None:
        """Helper to check and signal any pending close Future for a given FD."""
        if fd in _CLOSE_FUTURES:
            future = _CLOSE_FUTURES.pop(fd)
            if not future.done():
                # Use call_soon to execute the signaling safely in the event loop thread
                self.call_soon(future.set_result, True)
                print(f"✅ FD={fd} removal detected. Signaling Future.") # Debug line

    """
    Needed for TCP cleanup.
    """
    def _remove_reader(self, fd):
        self._signal_fd_removal(fd)
        super()._remove_reader(fd)

    """
    Needed for UDP cleanup.
    """
    def _remove_writer(self, fd):
        self._signal_fd_removal(fd)
        super()._remove_writer(fd)
        
    def remove_handler(self, fd: int) -> None:
        """
        Intercepts removal of generic handlers. This covers FDs not specifically 
        added as a reader or writer, but still being monitored (like listener sockets).
        """
        self._signal_fd_removal(fd)
        super().remove_handler(fd)

class ProxySelector:
    """A wrapper around the actual selector object to intercept unregister calls."""
    
    def __init__(self, selector_instance, loop):
        self._selector = selector_instance
        self._loop = loop
        # Copy public methods needed by the loop
        self.select = selector_instance.select
        self.close = selector_instance.close
        self.register = selector_instance.register
        self.get_map = selector_instance.get_map
        self.get_key = selector_instance.get_key

    def _maybe_signal_removal(self, fd: int, events: int, data: tuple) -> None:
        """Helper to signal the future if the FD is being completely unregistered."""
        
        # Check if the FD's future exists
        if fd not in _CLOSE_FUTURES:
            return

        # If events is 0 (unregister) OR data is None (usually only the loop's internal cleanup)
        # OR if we detect the last reader/writer being removed (as in your example logic)
        
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
        """Intercepts modification, checking if the FD is effectively unregistered."""
        # Your custom check logic should go here:
        if events == 0:
            # If the FD is modified to watch for 0 events, it's equivalent to unregister.
            self._maybe_signal_removal(fd, 0, None)
        elif events != 0:
            # Check if an existing FD is being modified to watch for 0 events (e.g., in a complex cleanup)
            # NOTE: This is tricky, the SelectorEventLoop internal logic mostly handles this.
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
        if fd not in _CLOSE_FUTURES:
            _CLOSE_FUTURES[fd] = self.create_future()

        return _CLOSE_FUTURES[fd]

class CustomEventLoopPolicy(asyncio.DefaultEventLoopPolicy):
    @staticmethod
    def exception_handler(self, context):
        log("exception handler")
        log(context)

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