import asyncio
import socket # For type hinting
import selectors
from ..utility.utils import *

# Map: FD -> Future object
_CLOSE_FUTURES: dict[int, asyncio.Future] = {}

class CustomEventLoop(asyncio.SelectorEventLoop):
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

    def remove_reader(self, fd: int) -> None:
        """Intercepts removal of read events."""
        self._signal_fd_removal(fd)
        super().remove_reader(fd)
        
    def remove_writer(self, fd: int) -> None:
        """Intercepts removal of write events."""
        self._signal_fd_removal(fd)
        super().remove_writer(fd)

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