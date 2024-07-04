import asyncio
from .utils import *
from .net import *
from .bind import *
from .pipe_events import *

"""
StreamReaderProtocol provides a way to "translate" between
Protocol and StreamReader. Mostly we're interested in having
a protocol class for TCP that can handle messages as they're
ready as opposed to having to poll ourself. Encapsulates
a client connection to a TCP server in a BaseProto object.
"""
class TCPEvents(asyncio.StreamReaderProtocol):
    def __init__(self, stream_reader, pipe_events, loop, conf=NET_CONF):
        # Setup stream reader / writers.
        super().__init__(stream_reader, lambda x, y: 1, loop=loop)

        # This is the server that spawns these client connections.
        self.pipe_events = pipe_events
        self.loop = loop

        # Will represent us.
        # Servers route above will be reused for this.
        self.client_events = None
        self.client_offset = 0

        # Main class variables.
        self.sock = None
        self.transport = None
        self.remote_tup = None
        self.conf = conf

    """
    StreamReaderProtocol has a bug in this function and doesn't
    properly return False. This is a patch.
    """
    def eof_received(self):
        #self.transport.pause_reading()
        reader = self._stream_reader
        if reader is not None:
            reader.feed_eof()
            
        return False

    def connection_made(self, transport):
        # Wrap this connection in a BaseProto object.
        self.transport = transport
        self.sock = transport.get_extra_info('socket')
        self.remote_tup = self.sock.getpeername()
        self.client_events = PipeEvents(
            sock=self.sock,
            route=self.pipe_events.route,
            conf=self.conf,
            loop=self.loop
        )

        # Log connection details.
        log(f"New TCP client l={self.sock.getsockname()}, r={self.remote_tup}")

        # Setup stream object.
        self.client_events.set_endpoint_type(TYPE_TCP_CLIENT)
        self.client_events.msg_cbs = self.pipe_events.msg_cbs
        self.client_events.end_cbs = self.pipe_events.end_cbs
        self.client_events.up_cbs = self.pipe_events.up_cbs
        self.client_events.connection_made(transport)

        # Record destination.
        self.client_events.stream.set_dest_tup(self.remote_tup)

        # Record instance to allow cleanup in server.
        self.pipe_events.add_tcp_client(self.client_events)

        # Setup handle for writing.
        super().connection_made(transport)
        self.client_events.stream.set_handle(
            self._stream_writer,

            # Index writers by peer connection.
            self.remote_tup
        )

    # If close was called on a pipe on a server then clients will already be closed.
    # So this code will have no effect.
    def connection_lost(self, exc):
        super().connection_lost(exc)

        # Cleanup client futures entry.
        p_client_entry = self.client_events.p_client_entry
        client_future = self.pipe_events.client_futures[p_client_entry]
        if client_future.done():
            del self.pipe_events.client_futures[p_client_entry]

        # Run disconnect handlers if any set.
        client_tup = self.remote_tup
        self.client_events.run_handlers(self.client_events.end_cbs, client_tup)

        # Close its client socket and transport.
        try:
            if self.client_events in self.pipe_events.tcp_clients:
                self.pipe_events.tcp_clients.remove(self.client_events)
        except Exception:
            log_exception()

        try:
            self.transport.close()
            self.transport = None
        except Exception:
            log_exception()

        # Remove this as an object to close and manage in the server.
        super().connection_lost(exc)

    def error_received(self, exp):
        pass

    def data_received(self, data):
        # This just adds data to reader which we are handling ourselves.
        #super().connection_lost(exc)
        if self.client_events is None:
            return

        if not len(self.client_events.msg_cbs):
            log("No msg cbs registered for inbound message in hacked tcp server.")

        self.client_events.handle_data(data, self.remote_tup)

# Returns a hacked TCP server object
async def handle_tcp_events(sock, pipe_events, *, loop=None, conf=NET_CONF, **kwds):
    # Main vars.
    loop = loop or asyncio.get_event_loop()
    def factory():
        reader = asyncio.StreamReader(limit=conf["reader_limit"], loop=loop)
        return TCPEvents(
            reader,
            pipe_events,
            loop,
            conf
        )

    # Call the regular create server func with custom protocol factory.
    server = await loop.create_server(
        factory,
        sock=sock,
        **kwds
    )

    return server

"""
In the spirit of unix a 'pipe' is an protocol and destination
agnostic way to send data. It supports TCP & UDP: cons & servers.
It supports using IPv4 and IPv6 destination addresses.
You can pull data from it based on a regex pattern.
You can execute code on new messages or connection disconnects.
"""
async def pipe_open(proto, dest=None, route=None, sock=None, msg_cb=None, up_cb=None, conf=NET_CONF):
    # If no route is set assume default interface route 0.
    if route is None:
        from .interface import Interface

        # Load internal addresses.
        i = await Interface()

        # Bind to route 0.
        route = await i.route()

    # If dest has no route set use this route.
    if dest is not None and dest.route is None:
        if not dest.resolved:
            dest.route = route
            await dest

    # Build the base protocol object.
    pipe_events = None
    try:
        # Get event loop reference.
        if conf["loop"] is not None:
            loop = conf["loop"]()
        else:
            loop = asyncio.get_event_loop()

        # Build socket bound to specific interface.
        if sock is None:
            sock = await socket_factory(
                route=route,
                dest_addr=dest,
                sock_type=UDP if proto == RUDP else proto,
                conf=conf
            )

            print(sock)
        

            # Check if sock succeeded.
            if sock is None:
                log("Could not allocate socket.")
                return None

            # Connect socket if TCP.
            if proto == TCP and dest is not None:
                print(dest.tup)

                # Set non-blocking.
                sock.settimeout(0)
                sock.setblocking(0)

                # Connect the socket task.
                con_task = asyncio.create_task(
                    loop.sock_connect(
                        sock, 
                        dest.tup
                    )
                )
                
                # Wait for connection, async style.
                await asyncio.wait_for(con_task, conf["con_timeout"])
                print(sock)
                    
        # Make sure bind port is set (and not zero.)
        route.bind_port = sock.getsockname()[1]

        # Return the sock instead of base proto.
        if conf["sock_only"]:
            return sock

        # Main protocol instance for routing messages.
        #if base_proto is None:
        pipe_events = PipeEvents(sock=sock, route=route, loop=loop, conf=conf)

        # Add message handler.
        if msg_cb is not None:
            pipe_events.add_msg_cb(msg_cb)

        # Start processing messages for UDP.
        if proto in [UDP, RUDP]:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: pipe_events,
                sock=sock
            )

            await pipe_events.stream_ready.wait()
            pipe_events.stream.set_handle(transport, client_tup=None)
            if dest is not None:
                pipe_events.set_endpoint_type(TYPE_UDP_CON)
            else:
                pipe_events.set_endpoint_type(TYPE_UDP_SERVER)

        # Install default ack builder and handler.
        # Now it is poorman's TCP ;_____; but still no ordering.
        if proto == RUDP:
            pipe_events.set_ack_handlers(
                is_ack=pipe_events.stream.is_ack,
                is_ackable=pipe_events.stream.is_ackable
            )

        # Start processing messages for TCP.
        if proto == TCP:
            # Add new connection handler.
            if up_cb is not None:
                pipe_events.add_up_cb(up_cb)

            # Listen server.
            if dest is None:
                # Start router for TCP messages.
                server = await handle_tcp_events(
                    sock=sock,
                    pipe_events=pipe_events,
                    loop=loop,
                    conf=conf
                )

                # Make the server start serving requests.
                assert(server is not None)
                pipe_events.set_tcp_server(server)

                # Saving the task is apparently needed
                # or the garbage collector could close it.
                if hasattr(server, "serve_forever"):
                    server_task = asyncio.create_task(
                        async_wrap_errors(
                            server.serve_forever()
                        )
                    )
                    
                    pipe_events.set_tcp_server_task(server_task)

                pipe_events.set_endpoint_type(TYPE_TCP_SERVER)

            # Single connection.
            if dest is not None:
                # Enable SSL on this socket.
                if conf["use_ssl"]:
                    # Some security options are disabled for simplicity.
                    # TODO: explore this more.
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False 
                    ssl_context.verify_mode = ssl.CERT_NONE
                    server_hostname = ""
                else:
                    ssl_context = False
                    server_hostname = None

                # base_proto.set_handle(writer, sock.getpeername())
                await loop.create_connection(
                    protocol_factory=lambda: pipe_events,
                    sock=sock,
                    ssl=ssl_context,
                    server_hostname=server_hostname
                )

                # Set transport handle.
                await pipe_events.stream_ready.wait()
                pipe_events.stream.set_handle(pipe_events.transport, dest.tup)
                pipe_events.set_endpoint_type(TYPE_TCP_CON)

        # Set dest if it's present.
        if dest is not None:
            pipe_events.stream.dest = dest
            pipe_events.stream.set_dest_tup(dest.tup)

            # Queue all messages for convenience.
            pipe_events.subscribe(SUB_ALL)

        # Register pipes, msg callbacks, and subscriptions.
        return pipe_events
    except Exception as e:
        log_exception()

        """
        Enables closing the socket if an error occurs.
        Don't remove this conditional code as it's
        needed to support TCP hole punching.
        """
        if conf["do_close"]:
            if sock is not None:
                log(f"closing socket. {sock.getsockname()}")
                sock.close()
            
            if pipe_events is not None:
                log("closing bas proto")
                await pipe_events.close()

async def pipe_utils_workspace():
    from .address import Address
    from .interface import Interface

    i = await Interface()
    dest = Address("google.com", 80)
    r = await i.route()
    p = await pipe_open(TCP, dest, r)
    print(p.sock)
    await p.close()

if __name__ == "__main__":
    async_test(pipe_utils_workspace)