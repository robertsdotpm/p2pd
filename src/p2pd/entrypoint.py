import multiprocessing
import asyncio
import socket
from .utility.utils import *
from .nic.interface_utils import *

class SelectorEventPolicy(asyncio.DefaultEventLoopPolicy):
    @staticmethod
    def exception_handler(self, context):
        log("exception handler")
        log(context)

    @staticmethod
    def loop_setup(loop):
        loop.set_debug(False)
        loop.set_exception_handler(SelectorEventPolicy.exception_handler)
        loop.default_exception_handler = SelectorEventPolicy.exception_handler

    def new_event_loop(self):
        selector = selectors.SelectSelector()
        loop = asyncio.SelectorEventLoop(selector)
        SelectorEventPolicy.loop_setup(loop)
        return loop

def p2pd_setup_event_loop():
    # If default isn't spawn then change it.
    # But only if it hasn't already been set.
    if multiprocessing.get_start_method() != "spawn":
        start_method = multiprocessing.get_start_method(allow_none=True)

        # First time setting this otherwise it will throw an error.
        if start_method is None:
            multiprocessing.set_start_method("spawn")

    """
    if platform.system() == "Windows":
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
            return
    """

    # Set the event loop policy to the selector if its not.
    policy = asyncio.get_event_loop_policy()
    if not isinstance(policy, SelectorEventPolicy):
        asyncio.set_event_loop_policy(SelectorEventPolicy())

    #sys.excepthook = my_except_hook

async def init_p2pd():
    global ENABLE_UDP
    global ENABLE_STUN

    # Setup event loop.
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    loop.set_exception_handler(SelectorEventPolicy.exception_handler)
    
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
    netifaces = Interface.get_netifaces()
    if netifaces is None:
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

        Interface.get_netifaces = lambda: netifaces

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

    return netifaces