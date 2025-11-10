import asyncio
from ...utility.utils import *
from ..net_utils import *
from ..bind import *
from .pipe_events import *
from ..address import *
from ..asyncio.asyncio_patches import *
from .pipe_defs import *



"""
StreamReaderProtocol provides a way to "translate" between
Protocol and StreamReader. Mostly we're interested in having
a protocol class for TCP that can handle messages as they're
ready as opposed to having to poll ourself. Encapsulates
a client connection to a TCP server in a BaseProto object.
"""
class TCPClientProtocol(asyncio.StreamReaderProtocol):
    def __init__(self, stream_reader, pipe_events, loop, conf=NET_CONF):
        """
        Patch for Python 3.13. Would be SOOOO fun if the Python
        brainlets stopped randomly breaking the whole f***ing project. 
        """
        def set_streams(_reader, _writer):
            if not hasattr(self, "_stream_reader"):
                self._stream_reader = _reader

            if not hasattr(self, "_stream_writer"):
                self._stream_writer = _writer
                
            return 1

        # Setup stream reader / writers.
        super().__init__(stream_reader, set_streams, loop=loop)

        """
        PipeEvents is created once before creating the main server with
        create_tcp_server -- but importantly: its not actually used
        as an event-driven class for protocol class events directly.
        It instead acts as a container and API to work with the existing
        code base and this class here passes events on to that class
        for TCP-based client messages.
        """
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
        p2pd_fds.add(self.sock)

        self.remote_tup = self.sock.getpeername()
        self.client_events = PipeEvents(
            sock=self.sock,
            route=self.pipe_events.route,
            conf=self.conf,
            loop=self.loop
        )

        # Log connection details.
        log(
            fstr(
                "New TCP client l={0}, r={1}", (
                self.sock.getsockname(), 
                self.remote_tup,
            ))
        )

        # Setup stream object.
        self.client_events.set_endpoint_type(TYPE_TCP_CLIENT)
        self.client_events.msg_cbs = self.pipe_events.msg_cbs
        self.client_events.end_cbs = self.pipe_events.end_cbs
        self.client_events.up_cbs = self.pipe_events.up_cbs
        self.client_events.connection_made(transport)
        self.client_events._stream_writer = self._stream_writer

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

        # Set on close event.
        self.client_events.on_close.set()

        # Close its client socket and transport.
        """
        Will lead to issues iterating on closing TCP clients?
        try:
            if self.client_events in self.pipe_events.tcp_clients:
                self.pipe_events.tcp_clients.remove(self.client_events)
        except Exception:
            log_exception()
        """

        """
        Transport should be closed if this is called?
        try:
            self.transport.close()
            self.transport = None
        except Exception:
            log_exception()
        """

        # Remove this as an object to close and manage in the server.
        #super().connection_lost(exc)

    def error_received(self, exp):
        log_exception()
        raise exp

    def data_received(self, data):
        log(fstr("Base proto recv tcp client = {0}", (data,)))
        # This just adds data to reader which we are handling ourselves.
        #super().connection_lost(exc)
        if self.client_events is None:
            return

        if not len(self.client_events.msg_cbs):
            log("No msg cbs registered for inbound message in hacked tcp server.")

        self.client_events.handle_data(data, self.remote_tup)

# Returns a hacked TCP server object
async def create_tcp_server(sock, pipe_events, *, loop=None, conf=NET_CONF, **kwds):
    # Main vars.
    loop = loop or asyncio.get_event_loop()
    def factory():
        reader = asyncio.StreamReader(limit=conf["reader_limit"], loop=loop)
        return TCPClientProtocol(
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