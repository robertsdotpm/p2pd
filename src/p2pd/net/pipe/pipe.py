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
from ..asyncio.async_run import *
from .pipe_tcp_events import *
from ..socket import *
from .pipe_defs import *

class PipeError(Exception):
    pass

class Pipe:
    def __init__(self, proto, dest=None, route=None, sock=None, conf=NET_CONF):
        self.proto = proto
        self.sock = sock
        self.route = route
        self.dest = dest
        self.pipe_events = None
        self.conf = conf or {}
        self.owns_socket = sock is None
        if sock is not None:
            log("Warning: externally provided socket will not be closed by Pipe")

        self._opened = False
        self._closed = False

    async def connect(self, msg_cb=None, up_cb=None):
        """
        Opens the pipe, resolves route/dest, creates socket and PipeEvents.
        Safe to call multiple times.
        """
        if self._opened:
            return self

        do_connect = self.sock == None
        try:
            await self.resolve_route_and_dest()
            await self.create_or_use_socket()
            if do_connect:
                await self.tcp_client_connect_if_needed()
                
            await self.setup_pipe_events(msg_cb, up_cb)
            self._opened = True
        except Exception:
            # defensive cleanup
            self.cleanup_on_error()
            raise

        return self
    
    async def close(self):
        if self.pipe_events is not None:
            await self.pipe_events.close()

    async def accept(self):
        if self.pipe_events is not None:
            return await self.pipe_events.make_awaitable()

    # Pretend to be a pipe_client.
    def __getattr__(self, name):
        """
        Redirect attribute access to self.pipe_events if it exists.
        Called only if the attribute doesn't exist on self.
        """
        if self.pipe_events is not None:
            try:
                return getattr(self.pipe_events, name)
            except AttributeError:
                pass

        raise AttributeError("'Pipe' object has no attribute " + str(name))

    # -----------------------------
    # Async context manager support
    # -----------------------------
    async def __aenter__(self):
        # Simply return self; connect() must be awaited before using async with
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()

    # -----------------------------
    # Wrapper to allow 'async with Pipe(...).session()'
    # -----------------------------
    def session(self, msg_cb=None, up_cb=None):
        """
        Returns an awaitable object that opens the pipe and supports async with.
        """
        pipe = self

        class _PipeAwaitableContext:
            def __init__(self):
                self._pipe = pipe

            def __await__(self):
                return pipe.connect(msg_cb, up_cb).__await__()

            async def __aenter__(self):
                # Ensure pipe is fully opened
                await pipe.connect(msg_cb, up_cb)
                return pipe

            async def __aexit__(self, exc_type, exc, tb):
                await pipe.close()

        return _PipeAwaitableContext()

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
        if route is not None and route.__name__ == "Interface":
            nic = route

            # For legacy code that passes Interface.
            route = nic.route()

        # If no route is set -- load a default interface.
        # This is slow and is used as a fallback.
        if route is None:
            from ...nic.interface import Interface
            nic = await Interface()
            route = await nic.route(af)

        # Routes all need to be bound.
        if not route.resolved:
            log("Resolve route received unbound route.")
            await route.bind()

        return route

    async def resolve_dest(self, dest, route, conf):
        """
        Converts dest into an Address instance if necessary.
        Supports IP:port tuples, int IPs, bytes, IPRange, or Address instances.
        """
        if dest is None:
            return None

        # For IPv6: dest tuples still need an interface to work correctly.
        if isinstance(dest, (list, tuple)):
            ip, port = dest

            # Supports int for IP, converts using CIDR
            if isinstance(ip, int):
                af = route.af
                cidr = CIDR_WAN if af is None else af_to_cidr(af)
                ip = IPRange(ip, cidr=cidr)

            # Normalize IPRange
            if isinstance(ip, IPRange):
                ip = ipr_norm(ip)

            # Standard address class for resolving addresses.
            dest = Address(ip, port, conf=conf)

        # Ensure address instances are resolved to IPs.
        if isinstance(dest, Address):
            if not dest.resolved:
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

            # Failed to get a socket.
            if self.sock is None:
                raise PipeError("Socket allocation failed")
            
            # Record socket ownership state.
            p2pd_fds.add(self.sock)
            self.owns_socket = True

        # Routes can specify binding on port 0.
        # Resolve the port that the route ended up on.
        self.route.bind_port = self.sock.getsockname()[1]

    async def tcp_client_connect_if_needed(self):
        """
        Connects TCP socket to remote dest if this is a TCP client.
        Sets non-blocking mode.
        """
        if self.proto == TCP and self.dest is not None:
            loop = await self.get_loop()
            self.sock.settimeout(0)
            self.sock.setblocking(0)
            timeout = self.conf.get("con_timeout", 5)
            success = False
            con_task = asyncio.create_task(
                loop.sock_connect(
                    self.sock, 
                    self.dest.tup
                )
            )

            # Wait for connection, async style.
            await asyncio.wait_for(con_task, self.conf["con_timeout"])

            """
            try:
                success = await asyncio.wait_for(
                    safe_sock_connect(loop, self.sock, self.dest.tup), 
                    timeout
                )
            except asyncio.TimeoutError:
                # Don't cancel underlying connect
                pass

            if not success:
                raise PipeError("Pipe error for safe sock connect.")
            """

    async def setup_pipe_events(self, msg_cb=None, up_cb=None):
        """
        Sets up PipeEvents for the pipe.
        Configures UDP/TCP, RUDP ack handlers, SSL, subscriptions, callbacks.
        """
        if self.conf.get("sock_only"):
            return

        """
        PipeEvents implements the same methods as asyncio Protocol classes
        but it also allows for send/recv and a few other methods.
        So code can be written in different styles.
        """
        loop = await self.get_loop()
        self.pipe_events = PipeEvents(
            sock=self.sock, 
            route=self.route, 
            loop=loop, 
            conf=self.conf
        )

        # Manually set some attributes in pipe events not in constructor.
        self.pipe_events.proto = self.proto
        if msg_cb:
            self.pipe_events.add_msg_cb(msg_cb)

        # UDP / RUDP setup
        if self.proto in (UDP, RUDP):
            # Create a new protocol-based datagram transport.
            transport, _ = await create_datagram_endpoint(
                loop, 
                lambda: self.pipe_events, 
                sock=self.sock
            )

            # Likely never triggered as exceptions are raised instead.
            if transport is None:
                raise PipeError("Failed to create datagram endpoint")

            # ---------------------------
            # Non-cancelling wait pattern
            # ---------------------------
            fut = asyncio.ensure_future(self.pipe_events.stream_ready.wait())
            try:
                await asyncio.wait_for(fut, timeout=2)
            except asyncio.TimeoutError:
                # Don't cancel underlying event; UDP may still be ready later
                pass

            # Record type of transport in pipe events.
            self.pipe_events.stream.set_handle(transport, client_tup=None)
            if self.dest is not None:
                self.pipe_events.set_endpoint_type(TYPE_UDP_CON)
            else:
                self.pipe_events.set_endpoint_type(TYPE_UDP_SERVER)

        # RUDP ack handlers
        if self.proto == RUDP:
            self.pipe_events.set_ack_handlers(
                is_ack=self.pipe_events.stream.is_ack,
                is_ackable=self.pipe_events.stream.is_ackable
            )

        # TCP setup
        if self.proto == TCP:
            # Add new connection handler.
            if up_cb:
                self.pipe_events.add_up_cb(up_cb)

            if self.dest is None:
                # Start router for TCP messages.
                server = await create_tcp_server(
                    sock=self.sock,
                    pipe_events=self.pipe_events,
                    loop=loop,
                    conf=self.conf
                )

                # Check transport started successfully.
                if server is None:
                    raise PipeError("Failed to create TCP server")
                
                # Save transport returned from create server.
                self.pipe_events.set_tcp_server(server)

                # Saving the task is apparently needed
                # or the garbage collector could close it.
                if hasattr(server, "serve_forever"):
                    self.pipe_events.set_tcp_server_task(
                        asyncio.ensure_future(
                            async_wrap_errors(server.serve_forever())
                        )
                    )

                # Store type of endpoint in pipe events.
                self.pipe_events.set_endpoint_type(TYPE_TCP_SERVER)
            else:
                # TCP client
                if self.conf.get("use_ssl"):
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    server_hostname = ""
                    wrap_overhead = 5
                else:
                    ctx = None
                    server_hostname = None
                    wrap_overhead = 2

                # Wrap an already connected TCP socket.
                await loop.create_connection(
                    lambda: self.pipe_events, 
                    sock=self.sock, 
                    ssl=ctx, 
                    server_hostname=server_hostname
                )

                # ---------------------------
                # Non-cancelling wait pattern
                # ---------------------------
                fut = asyncio.ensure_future(self.pipe_events.stream_ready.wait())
                try:
                    await asyncio.wait_for(fut, timeout=wrap_overhead)
                except asyncio.TimeoutError:
                    pass

                # Set the con handles.
                self.pipe_events.stream.set_handle(
                    self.pipe_events.transport, 
                    self.dest.tup
                )

                # Indicate endpoint is for a TCP con.
                self.pipe_events.set_endpoint_type(TYPE_TCP_CON)

        # Set dest and subscribe if no msg_cb
        if self.dest:
            self.pipe_events.stream.dest = self.dest
            self.pipe_events.stream.set_dest_tup(self.dest.tup)
            if not msg_cb:
                self.pipe_events.subscribe(SUB_ALL)

    def cleanup_on_error(self):
        """
        Closes socket if owned. Removes it from p2pd_fds.
        Resets self.sock and self.owns_socket to prevent reuse.
        Idempotent.
        """
        if getattr(self, "_closed", False):
            return

        if self.owns_socket and self.sock:
            try:
                self.sock.close()
            except Exception:
                log_exception()
            if self.sock in p2pd_fds:
                p2pd_fds.discard(self.sock)

        # Clear state
        self.sock = None
        self.owns_socket = False
        self._closed = True

async def sock_to_pipe(sock, nic):
    # Useful variables from the socket.
    af = sock.family
    bind_tup = sock.getsockname()
    bind_ipr = IPR(bind_tup[0], af=af)
    bind_port = bind_tup[1] 

    # Find a pre-existing route for this bind IP.
    # Comparisons use IPRange to normalise IPs.
    use_route = None
    for route in nic.rp[af]:
        if bind_ipr in route.nic_ips:
            use_route = route
            break
        if bind_ipr in route.link_locals:
            use_route = route
            break

    """
    If the associated route for the bind IP can't be found
    for the NIC then raise an exception. If the bind IP
    was set to loopback or all addresses -- set to new route.
    """
    if not use_route:
        not_nic_ips = VALID_LOOPBACKS + VALID_ANY_ADDR
        if bind_tup[0] in not_nic_ips:
            use_route = nic.route(af)
        else:
            raise Exception("Cannot find associated route for NIC bind.")

    # Associate a particular route with a bound port.
    await use_route.bind(port=bind_port)

    # Setup the pipe at that route.
    pipe = await Pipe(
        sock.type, # Transport protocol.
        bind_tup[:2], # Dest tup turned to Addr by resolving (no DNS calls.)
        use_route, # Route associated with a nic and bind details.
        sock=sock # The actual socket.
    ).connect() # Won't connect when socket is passed.

    # Return pipe.
    return pipe