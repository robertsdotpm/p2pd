"""
- pipe_open allows multiple encoding forms to be used for the IP
field. But bytes is a little unclear. Is it the raw bytes of
an IP address or is it a human-readable IP in ASCII? I
decided to default to the latter otherwise devs. But you
can still pass in ints or IPRanges to use raw IPs. With
ints just make sure there is a route alongside it because
the address family is needed to disambiguate whether the
int is a short IPv6 or an IPv4.

- theres a bug on ancient operating systems (Windows Vista)
where await sock_event with wait_for can crash the event loop.
The fix has been merged in >= 3.7.5 which also works on Vista.
I wasn't even able to get Python 3 to run on XP so for now it
isn't supported. Trying to merge Python fixes for older OSes
isn't a priority so these users should be told to upgrade
Python versions if they get bugs with the event loop.

https://bugs.python.org/issue34795
"""

import asyncio
from ...utility.utils import *
from ..net_utils import *
from ..bind import *
from .pipe_events import *
from ..address import Address
from ..ip_range import IPRange
from ..address import *
from ..asyncio.asyncio_patches import *
from .pipe_tcp_events import *
from ..socket import *
from .pipe_defs import *

# Patch _select if needed.
# This fixes a bug on Windows Vista / older versions
# where await sock_event with wait_for
# can crash the event loop. See Python bug 34795.
if sys.platform == 'win32':
    if SelectSelector._select != patched_select:
        SelectSelector._select = patched_select

class PipeError(Exception):
    pass

class Pipe:
    def __init__(self, proto, sock=None, route=None, dest=None, conf=None):
        self.proto = proto
        self.sock = sock
        self.route = route
        self.dest = dest
        self.pipe_events = None
        self.conf = conf or {}
        self.owns_socket = False

    @classmethod
    async def open(cls, proto, dest=None, route=None, sock=None, msg_cb=None, up_cb=None, conf=None):
        """
        Opens a pipe, fully async. Supports TCP/UDP/RUDP clients and servers.
        Automatically resolves route and destination, creates socket, and sets up PipeEvents.
        """
        pipe = cls(proto, sock=sock, route=route, dest=dest, conf=conf)
        try:
            await pipe.resolve_route_and_dest()
            await pipe.create_or_use_socket()
            await pipe.tcp_client_connect_if_needed()
            await pipe.setup_pipe_events(msg_cb, up_cb)
            return pipe
        except Exception:
            # Ensures socket and resources are closed on error
            await pipe.close()
            raise

    # -----------------------------
    # Async context manager support
    # -----------------------------
    def __await__(self):
        return self._enter().__await__()

    async def _enter(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        # Cleanup pipe automatically on exit
        await self.close()

    # -----------------------------
    # Public helper methods
    # -----------------------------
    async def get_loop(self):
        if self.conf.get("loop") is not None:
            return self.conf["loop"]()
        return asyncio.get_event_loop()

    async def resolve_route_and_dest(self):
        af_hint = getattr(self.route, "af", None)
        self.route = await self.resolve_route(self.route, af_hint)
        self.dest = await self.resolve_dest(self.dest, self.route, self.conf)

    async def resolve_route(self, route, af):
        """
        Resolves the route to bind the socket.
        Covers the case where a network Interface is passed instead of a route.
        In that case, just use the first available route at first supported AF.
        """
        if route is not None and getattr(route, "__name__", None) == "Interface":
            nic = route
            # For legacy code that passes Interface, get its first route
            route = nic.route()  # may need await if route() is async

        if route is None:
            from ...nic.interface import Interface
            iface = await Interface()
            route = await iface.route(af)

        if not getattr(route, "resolved", False):
            await route.bind()

        return route

    async def resolve_dest(self, dest, route, conf):
        """
        Converts dest into an Address instance if necessary.
        Supports IP:port tuples, int IPs, bytes, IPRange, or Address instances.
        """
        if dest is None:
            return None

        if isinstance(dest, (list, tuple)):
            ip, port = dest

            # Supports int for IP, converts using CIDR
            if isinstance(ip, int):
                cidr = getattr(route, "af", None)
                cidr = "WAN" if cidr is None else af_to_cidr(route.af)
                ip = IPRange(ip, cidr=cidr)

            # Normalize IPRange
            if isinstance(ip, IPRange):
                ip = ipr_norm(ip)

            dest = Address(ip, port, conf=conf)

        if isinstance(dest, Address):
            if not getattr(dest, "resolved", False):
                await dest.res(route)
            # Select compatible IP for route AF
            dest = dest.select_ip(route.af)

        return dest

    async def create_or_use_socket(self):
        """
        Creates a socket if none was passed in, bound to route.
        Adds socket to global p2pd_fds set.
        Sets route.bind_port to the bound local port.
        """
        if self.sock is None:
            self.sock = await socket_factory(
                route=self.route,
                dest_addr=self.dest,
                sock_type=UDP if self.proto == RUDP else self.proto,
                conf=self.conf
            )
            if self.sock is None:
                raise PipeError("Socket allocation failed")
            p2pd_fds.add(self.sock)
            # Preserve bind_port for legacy code
            self.route.bind_port = self.sock.getsockname()[1]
            self.owns_socket = True

    async def connect_socket(self, loop, sock, dest, timeout):
        """
        Async TCP client connect helper.
        Raises PipeError on failure or timeout.
        """
        task = asyncio.ensure_future(safe_sock_connect(loop, sock, dest))
        try:
            is_connected = await asyncio.wait_for(task, timeout)
            if not is_connected:
                raise PipeError("Socket connection failed")
            return True
        except asyncio.TimeoutError:
            task.cancel()
            raise PipeError("TCP connection timeout")

    async def tcp_client_connect_if_needed(self):
        """
        Connects TCP socket to remote dest if this is a TCP client.
        Sets non-blocking mode.
        """
        if self.proto == TCP and self.dest is not None:
            self.sock.settimeout(0)
            self.sock.setblocking(0)
            loop = await self.get_loop()
            await self.connect_socket(
                loop,
                self.sock,
                self.dest,
                self.conf.get("con_timeout", 10)
            )

    async def setup_pipe_events(self, msg_cb=None, up_cb=None):
        """
        Sets up PipeEvents for the pipe.
        Configures UDP/TCP, RUDP ack handlers, SSL, subscriptions, callbacks.
        """
        if self.conf.get("sock_only"):
            return

        loop = await self.get_loop()
        self.pipe_events = PipeEvents(sock=self.sock, route=self.route, loop=loop, conf=self.conf)
        self.pipe_events.proto = self.proto

        if msg_cb:
            self.pipe_events.add_msg_cb(msg_cb)

        # UDP / RUDP setup
        if self.proto in (UDP, RUDP):
            transport, _ = await create_datagram_endpoint(loop, lambda: self.pipe_events, sock=self.sock)
            await self.pipe_events.stream_ready.wait()
            self.pipe_events.stream.set_handle(transport, client_tup=None)
            self.pipe_events.set_endpoint_type(TYPE_UDP_CON if self.dest else TYPE_UDP_SERVER)

        # RUDP ack handlers
        if self.proto == RUDP:
            self.pipe_events.set_ack_handlers(
                is_ack=self.pipe_events.stream.is_ack,
                is_ackable=self.pipe_events.stream.is_ackable
            )

        # TCP setup
        if self.proto == TCP:
            if up_cb:
                self.pipe_events.add_up_cb(up_cb)

            if self.dest is None:
                # TCP server
                server = await create_tcp_server(sock=self.sock, pipe_events=self.pipe_events, loop=loop, conf=self.conf)
                if server is None:
                    raise PipeError("Failed to create TCP server")
                self.pipe_events.set_tcp_server(server)
                if hasattr(server, "serve_forever"):
                    # Keep server task alive to prevent garbage collection
                    task = asyncio.ensure_future(async_wrap_errors(server.serve_forever()))
                    self.pipe_events.set_tcp_server_task(task)
                self.pipe_events.set_endpoint_type(TYPE_TCP_SERVER)
            else:
                # TCP client
                if self.conf.get("use_ssl"):
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    server_hostname = ""
                else:
                    ctx = None
                    server_hostname = None

                await loop.create_connection(lambda: self.pipe_events, sock=self.sock, ssl=ctx, server_hostname=server_hostname)
                await self.pipe_events.stream_ready.wait()
                self.pipe_events.stream.set_handle(self.pipe_events.transport, self.dest.tup)
                self.pipe_events.set_endpoint_type(TYPE_TCP_CON)

        # Set dest and subscribe if no msg_cb
        if self.dest:
            self.pipe_events.stream.dest = self.dest
            self.pipe_events.stream.set_dest_tup(self.dest.tup)
            if not msg_cb:
                self.pipe_events.subscribe(SUB_ALL)

    async def close(self):
        """
        Closes socket if owned. Removes it from p2pd_fds.
        """
        if self.owns_socket and self.sock:
            try:
                self.sock.close()
            except Exception:
                log_exception()
            if self.sock in p2pd_fds:
                p2pd_fds.discard(self.sock)
