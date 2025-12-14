import multiprocessing
import asyncio
import socket
import sys
from .settings import *
from .utility.utils import *
from .net.asyncio.event_loop import *
from .net.asyncio.async_run import *
from .net.asyncio.asyncio_patches import *
from .nic.interface_utils import *
if sys.platform == "win32":
    from .nic.netifaces.windows.win_netifaces import *
else:
    import netifaces as netifaces

_cached_netifaces = None
_cache_lock = asyncio.Lock()

"""
I've honestly never had success with using "async locks",
I've found it better to design the software in a way that it
avoids locks but we'll see if this works.

This is a critical function. It sets up the event loop properly
and dynamically loads netifaces based on the OS. I implement
a class-interface compatible version of netifaces for Windows
because the netifaces main class requires a crap load of binary
dependencies and I want my stuff to install easier.

My Windows netifaces stuff doesn't use the Win32 API directly
(too much effort) but it implements several scripting approaches
with regex and fallbacks if one doesn't work. To support all
Windows versions. It is slow but accesses some very complex
information and ends up being cached.

I have seen some interesting win32 api code in Python that does
similar stuff on Github. May be something to add in the future.
Otherwise -- the nix and BSD versions happily accept the regular
netifaces module from pypi which doesn't need deps to work.
"""
async def p2pd_setup_netifaces():
    global ENABLE_UDP
    global ENABLE_STUN
    global _cached_netifaces
    if _cached_netifaces is not None:
        return _cached_netifaces
    
    async with _cache_lock:
        # Double check inside lock
        if _cached_netifaces is not None:
            return _cached_netifaces

        # Setup event loop.
        loop = asyncio.get_event_loop()
        loop.set_debug(False)
        loop.set_exception_handler(CustomEventLoopPolicy.exception_handler)
        
        def fatal_error(self, exc, message='Fatal error on transport'):
            er = {
                'message': message,
                'exception': exc,
                'transport': self,
                'protocol': self._protocol,
            }
            log(er)

            # Should be called from exception handler only.
            #self.call_exception_handler(er)
            self._force_close(exc)

        asyncio.selector_events._SelectorTransport._fatal_error = fatal_error

        # Attempt to get monkey patched netifaces.
        if sys.platform == "win32":
            """
            loop = get_running_loop()

            # This happens if the asyncio REPL is used.
            # Nested event loops are a work around.
            if loop is not None:
                import nest_asyncio
                nest_asyncio.apply()
            """
            netifaces = await Netifaces().start()
        else:
            netifaces = sys.modules["netifaces"]

        # Are UDP sockets blocked?
        # Firewalls like iptables on freehosts can do this.
        sock = None
        try:
            # Figure out what address family default interface supports.
            if_name = get_default_iface(netifaces)
            af = get_interface_af(netifaces, if_name)
            if af == AF_ANY: # Duel stack. Just use v4.
                af = IP4

            # Set destination based on address family.
            if af == IP4:
                dest = ('8.8.8.8', 60000)
            else:
                dest = ('2001:4860:4860::8888', 60000)

            # Build new UDP socket.
            sock = socket.socket(family=af, type=socket.SOCK_DGRAM)

            # Attempt to send small msg to dest.
            sock.sendto(b'testing UDP. disregard this sorry.', 0, dest)
        except asyncio.CancelledError:
            raise
        except Exception:
            """
            Maybe in the future I write code as a fail-safe but for
            now I don't have time. It's better to show a clear reason
            why the library won't work then to silently fail.
            """
            raise Exception("Error this library needs UDP support to work.")
        

            ENABLE_UDP = False
            ENABLE_STUN = False
            log("UDP sockets blocked! Disabling STUN.")
            log_exception()
        finally:
            if sock is not None:
                sock.close()

        _cached_netifaces = netifaces
        return netifaces


def init_process_pool():
    # Make selector default event loop.
    # On Windows this changes it from proactor to selector.
    asyncio.set_event_loop_policy(CustomEventLoopPolicy())

    # Create new event loop in the process.
    loop = asyncio.get_event_loop()

    # Handle exceptions on close.
    loop.set_exception_handler(handle_exceptions)

def p2pd_setup_event_loop():
    # -----------------------------
    # Patch logic based on Python version
    # -----------------------------
    if sys.version_info >= (3, 7):
        # Modern Python
        SelectSelector._select = patched_select_modern
    else:
        # Older Python
        SelectSelector._select = patched_select_old

    # If default isn't spawn then change it.
    # But only if it hasn't already been set.
    if multiprocessing.get_start_method() != "spawn":
        start_method = multiprocessing.get_start_method(allow_none=True)

        # First time setting this otherwise it will throw an error.
        if start_method is None:
            multiprocessing.set_start_method("spawn")

    patch_asyncio_backports(CustomEventLoop)
    policy = asyncio.get_event_loop_policy()
    if not isinstance(policy, CustomEventLoopPolicy):
        asyncio.set_event_loop_policy(CustomEventLoopPolicy())

p2pd_setup_event_loop()

async def entrypoint_test():
    out = await p2pd_setup_netifaces()
    print(out)

if __name__ == "__main__": # pragma: no cover
    asyncio.run(entrypoint_test())