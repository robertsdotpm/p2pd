import asyncio
import re
import inspect
from .ack_udp import *
from .net import *

TYPE_UDP_CON = 1
TYPE_UDP_SERVER = 2
TYPE_TCP_CON = 3
TYPE_TCP_SERVER = 4
TYPE_TCP_CLIENT = 5
SUB_ALL = [b"", b""]

"""
The code in this class supports a pull / fetch style use-case.
More suitable for some apps whereas the parent class allows
for handles to handle messages as they come in. The fetching
API needs for messages to be subscribed to beforehand.
"""
class BaseStream(ACKUDP):
    def __init__(self, proto, loop=None, conf=NET_CONF):
        super().__init__()
        self.conf = conf
        self.dest_tup = None
        self.loop = loop or asyncio.get_event_loop()

        # [Bool(msg)] = Queue.
        # Lets convert this to [b"msg pattern", b"host pattern"] = [Queue]
        self.subs = {}

        # Instance of the base proto class.
        self.proto = proto
        self.route = self.proto.route

        # Used for doing send calls.
        self.handle = {}

    """
    (1) UDP is multiplexed and doesn't need a destination bound.
    (2) TCP cons have a dest set.
    (3) TCP and UDP servers won't have a dest.
    """
    def set_dest_tup(self, dest_tup):
        self.dest_tup = dest_tup

    """
    Set internal handle used for doing sends.
    For UDP this is a asyncio.DatagramTransport.
    For TCP it's a asyncio.StreamWriter.
    """
    def set_handle(self, handle, client_tup=None):
        if client_tup is not None:
            self.handle[client_tup] = handle
        else:
            self.handle = handle

    def hash_sub(self, sub):
        return hash(sub[0]) + hash(sub[1])

    # Subscribe to a certain message and host type.
    # sub = [b_msg_pattern, b_addr_pattern]
    def subscribe(self, sub, handler=None):
        offset = self.hash_sub(sub)
        if offset not in self.subs:
            self.subs[offset] = [
                sub,
                asyncio.Queue(self.conf["max_qsize"]),
                handler
            ]

        return self

    # Remove a subscription.
    def unsubscribe(self, sub):
        offset = self.hash_sub(sub)
        if offset in self.subs:
            del self.subs[offset]

        return self

    # Adds a message to the first valid bucket.
    """
    TODO: If the queue is full what should the default
    actions be? Should the program await the queue
    being empty? Should it discard data? Maybe on limit - 1
    call https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.remove_reader and on queue empty add it back.
    """
    def add_msg(self, data, client_tup):
        # No subscriptions.
        if not len(self.subs):
            log("no subs")
            return

        # Add message to queue and raise an event.
        def do_add(q):
            # Check queue isn't full.
            if q.full():
                # TODO: Remove sock from event select.
                # To give time for queue to be processed.
                q.get_nowait()

            # Put an item on the queue.
            assert(isinstance(client_tup, tuple))
            q.put_nowait([client_tup, data])

        # Apply bool filters to message.
        client_addr = b"%s:%d" % (to_b(client_tup[0]), client_tup[1])
        for sub, q, handler in self.subs.values():
            # Msg pattern, address pattern.
            b_msg_p, b_addr_p = sub

            # Check client_addr matches their host pattern.
            if b_addr_p:
                host_matches = re.findall(b_addr_p, client_addr)
                if host_matches == []:
                    continue

            # Check data matches their message pattern.
            if b_msg_p:
                msg_matches = re.findall(b_msg_p, data)
                if msg_matches == []:
                    continue

            # Execute message using handle instead of adding to queue.
            if handler is not None:
                log("handler not none.")
                run_handler(self.proto, handler, client_tup, data)
                continue

            # Add message to queue.
            do_add(q)

    # Async wait for a message that matches a pattern in a queue.
    async def recv(self, sub=SUB_ALL, timeout=2, full=False):
        recv_timeout = timeout or self.conf["recv_timeout"]
        offset = self.hash_sub(sub)
        try:
            # Sanity checking.
            if offset not in self.subs:
                raise Exception("Sub not found. Forgot to subscribe.")

            # Get message from queue with timeout.
            _, q, handler = self.subs[offset]
            ret = await asyncio.wait_for(
                q.get(),
                recv_timeout
            )

            # Run handler if one is set.
            if handler is not None:
                run_handler(self.proto, handler, ret[0], ret[1])

            # Return data, sender_tup.
            if full:
                return ret
            else:
                # Return only the data portion.
                return ret[1]
        except Exception as e:
            return None

    # Async send for TCP and UDP cons.
    # Listen servers also supported.
    async def send(self, data, dest_tup):
        try:
            # Get handle reference.
            if isinstance(self.handle, dict):
                handle = self.handle[dest_tup]
            else:
                handle = self.handle

            # TCP send -- already bound to a target.
            # Indexed by writer streams per con.
            if isinstance(handle, asyncio.streams.StreamWriter):
                handle.write(data)
                await handle.drain()
                return 1

            # UDP send -- not connected - can be sent to anyone.
            # Single handle for multiplexing.
            if isinstance(handle, DATAGRAM_TYPES):
                handle.sendto(
                    data,
                    dest_tup
                )
                return 1

            # TCP send -- already bound to transport con.
            # TCP Transport instance.
            if isinstance(handle, STREAM_TYPES):
                handle.write(data)

                """
                await self.loop.sock_sendall(
                    self.proto.sock,
                    data
                )
                """

                return 1

            return 0
        except Exception as e:
            log(f"{self.handle}")
            log_exception()
            return 0

"""
In Python's asyncio code you can use so-called 'protocol' classes
to receive messages from an endpoint or server and then handle
them in real time. This is a very elegant way to do things
because the event loop handles polling the sockets to check
if there's any new messages for you vs you doing the check
yourself using await. The drawback is the protocol-style way
of networking basically uses callbacks and by itself -- doesn't
mix well with the async way of doing things. But with some small
tweaks it is flexible enough to do whatever you want.
"""
class BaseProto(BaseACKProto):
    def __init__(self, sock, route=None, loop=None, conf=NET_CONF):
        super().__init__(conf)

        # Config.
        self.conf = conf
        self.loop = loop

        # Socket of underlying connection.
        self.sock = sock
        self.tcp_clients = []
        self.tcp_server = None
        self.tcp_server_task = None
        self.endpoint_type = None

        # Bind / route.
        self.route = route

        # Can have pipes to other streams that it broadcasts to.
        self.pipes = []

        # List of other pipes that pipe to this.
        self.parent_pipes = []

        # Process messages in real time.
        self.msg_cbs = []

        # Ran when a connection ends.
        self.end_cbs = []

        # List of tasks for send / recv / subscribe.
        """
        Coroutine references need to be saved or the garbage collector
        may clean them up. The list here is a generic list for async
        operations in motion as part of using this class -- possible
        operations like send / recv called via msg handlers may end
        up here and they're awaited for completion.
        """
        self.tasks = []

        # Tasks saved for running msg handlers.
        """
        When any message handlers that are coroutines are registered
        and run on a new message it's saved as a task in this list.
        These tasks aren't awaited for completion in close so
        that message handlers can call close themselves and not cause
        infinite waiting loops (their handler would never be 'done.'
        as it awaits on themself to finish.)
        Cleaned-up when a handler task is done.
        """
        self.handler_tasks = []

        # For unique messages if enabled.
        self.msg_ids = {}

        # Event fired when stream set.
        self.stream_ready = asyncio.Event()

        # Placeholders.
        self.transport = None
        self.stream = None
        self.is_ack = None
        self.is_ackable = None
        self.is_running = True

    # Indicates the type of endpoint this is.
    def set_endpoint_type(self, endpoint_type):
        self.endpoint_type = endpoint_type

    # Used for event-based programming.
    # Can execute code on new cons, dropped cons, and new msgs.
    def run_handlers(self, handlers, client_tup, data=None):
        # Run any registered call backs on msg.
        self.handler_tasks = rm_done_tasks(self.handler_tasks)
        for handler in handlers:
            # Run the handler as a callback or coroutine.
            run_handler(self, handler, client_tup, data)

    def get_client_tup(self):
        # Get transport address.
        client_tup = None
        if self.sock is not None:
            # Use local socket details (for servers.)
            client_tup = self.sock.getsockname()
            
            # Try use remote peer info if it exists.
            try:
                client_tup = self.sock.getpeername()
            except Exception:
                pass

        return client_tup

    def add_tcp_client(self, client):
        self.tcp_clients.append(client)

    def set_tcp_server(self, server):
        self.transport = server
        self.tcp_server = server

    def set_tcp_server_task(self, task):
        self.tcp_server_task = task

    def set_ack_handlers(self, is_ack, is_ackable):
        self.is_ack = is_ack
        self.is_ackable = is_ackable
        return self

    def add_pipe(self, pipe):
        self.pipes.append(pipe)
        pipe.parent_pipes.append(self)
        return self

    def del_pipe(self, pipe):
        if pipe in self.pipes:
            self.pipes.remove(pipe)

        return self

    def add_msg_cb(self, msg_cb):
        self.msg_cbs.append(msg_cb)
        return self

    def del_msg_cb(self, msg_cb):
        if msg_cb in self.msg_cbs:
            self.msg_cbs.remove(msg_cb)

        return self

    def add_end_cb(self, end_cb):
        self.end_cbs.append(end_cb)

        # Make sure it runs if this is already closed.
        if not self.is_running:
            self.run_handlers([end_cb])

        return self

    def del_end_cb(self, end_cb):
        if end_cb in self.end_cbs:
            self.end_cbs.remove(end_cb)

        return self

    # Called only once for UDP.
    def connection_made(self, transport):
        if self.stream is None:
            # Record the endpoint.
            if transport is not None:
                self.transport = transport

            # Set stream object for doing I/O.
            self.stream = BaseStream(self, loop=self.loop)
            self.stream_ready.set()

    # Socket closed manually or shutdown by other side.
    def connection_lost(self, exc):
        super().connection_lost(exc)

        # Remove self from any parent pipes.
        for pipe in self.parent_pipes:
            pipe.del_pipe(self)
        
        # Execute any cleanup handlers.
        client_tup = self.get_client_tup()
        self.run_handlers(self.end_cbs, client_tup)

    def route_msg(self, data, client_tup):
        # No data to route.
        if not data:
            return

        # Route messages to any pipes.
        for pipe in self.pipes:
            task = asyncio.create_task(
                pipe.send(
                    data,
                    pipe.stream.dest_tup
                )
            )

            self.tasks.append(task)

        # Add message to any interested subscriptions.
        # Matching pattern for host is in bytes so
        # there is a need to convert ip to bytes.
        self.stream.add_msg(
            data,
            (client_tup[0], client_tup[1])
        )

        # Process messages using any registered handlers.
        self.run_handlers(self.msg_cbs, client_tup, data)

    def handle_data(self, data, client_tup):
        # Convert data to bytes.
        if isinstance(data, bytearray):
            data = bytes(data)

        # Record msg received.
        log(
            'data recv {} = {}'.format(client_tup, data)
        )

        # Ack UDP msg if enabled.
        if self.is_ack and self.is_ackable:
            """
            Sends an ACK down the stream if it's a message that needs an ACK.
            Clients that use the 'reliable' UDP functions over a specific
            protocol provide their own functions for returning these ACKs.
            Hence the code works with any protocol.
            """
            did_ack, payload = self.stream.handle_ack(
                data,
                self.is_ack,
                self.is_ackable,
                lambda buf: self.stream.send(buf, client_tup)
            )

            """
            The Stream protocol class does not route back
            messages that are ACKs to messages we sent. Otherwise
            a sender might see a returned ACK and get into a loop
            trying to ACK it themself. It's a control message so
            there's no real reason to route them to recv.
            """
            if not did_ack:
                return
            else:
                # Strip the header portion out.
                data = payload

        # Supports unique messages.
        if self.conf["enable_msg_ids"]:
            if not self.is_unique_msg(self.stream, data, client_tup):
                log("not unique.")
                return

        # Route message to stream.
        self.route_msg(data, client_tup)

    # UDP packets.
    def datagram_received(self, data, client_tup):
        log(f"Base proto recv udp = {data}")
        if self.transport is None:
            log(f"Skipping process data cause transport none 1.")
            return

        self.handle_data(data, client_tup)

    # Single TCP connection.
    def data_received(self, data):
        log(f"Base proto recv tcp = {data}")
        if self.transport is None:
            log(f"Skipping process data cause transport none 2.")
            return

        self.handle_data(
            data,
            self.transport.get_extra_info('socket').getpeername()
        )

    async def close(self, do_sleep=True):
        # Already closed.
        if not self.is_running:
            return

        # Skip sleep for TCP clients.
        if do_sleep:
            await asyncio.sleep(0)

        """
        # Cancel serve forever.
        if self.tcp_server_task is not None:
            self.transport.shutdown()
        """

        # Wait for sending tasks in ACK UDP.
        if self.stream is not None:
            # Set ACKs for all sent messages.
            for seq_no in self.stream.seq.keys():
                self.stream.seq[seq_no].set()

            # Wait for all send loops to end.
            if len(self.stream.ack_send_tasks):
                await gather_or_cancel(self.stream.ack_send_tasks, 4)
                self.stream.ack_send_tasks = []

        # Wait for all current tasks to end.
        self.tasks = rm_done_tasks(self.tasks)
        if len(self.tasks):
            # Wait for tasks to finish.
            await gather_or_cancel(self.tasks, 4)
            self.tasks = []

        # Close spawned TCP clients for a TCP server.
        for client in self.tcp_clients:
            # Client is already closed.
            if not client.is_running:
                continue

            # Close client transports.
            await client.close(do_sleep=False)

        # Close the main server socket.
        # This does cleanup for any TCP servers.
        if self.transport is not None:
            self.transport.close()

        """
        # Close any sockets.
        if self.sock is not None:
            print("Closing sock")
            self.sock.close()
        """

        # No longer running.
        self.transport = None
        self.socket = None
        self.is_running = False
        self.tcp_server = None
        self.tcp_server_task = None
        self.tcp_clients = []

    # Return a matching message, async, non-blocking.
    async def recv(self, sub=SUB_ALL, timeout=2, full=False):
        return await self.stream.recv(sub, timeout, full)

    async def send(self, data, dest_tup=None):
        dest_tup = dest_tup or self.stream.dest_tup
        return await self.stream.send(data, dest_tup)

    # Sync subscribe to a message.
    # Easy way to get a message from sync code too.
    def subscribe(self, sub=SUB_ALL, handler=None):
        self.stream.subscribe(sub, handler)
        return self

    def unsubscribe(self, sub):
        self.stream.unsubscribe(sub)
        return self

    # Echo client just for testing.
    async def echo(self, msg, dest_tup):
        buf = bytearray().join([b"ECHO ", msg])
        await self.send(buf, dest_tup)

"""
StreamReaderProtocol provides a way to "translate" between
Protocol and StreamReader. Mostly we're interested in having
a protocol class for TCP that can handle messages as they're
ready as opposed to having to poll ourself. Encapsulates
a client connection to a TCP server in a BaseProto object.
"""
class BaseStreamReaderProto(asyncio.StreamReaderProtocol):
    def __init__(self, stream_reader, base_proto, loop, conf=NET_CONF):
        # Setup stream reader / writers.
        super().__init__(stream_reader, lambda r, w: 1, loop)

        # This is the server that spawns these client connections.
        self.proto = base_proto
        self.loop = loop

        # Will represent us.
        # Servers route above will be reused for this.
        self.client_proto = None

        # Main class variables.
        self.sock = None
        self.transport = None
        self.remote_tup = None
        self.conf = conf

    def connection_made(self, transport):
        # Wrap this connection in a BaseProto object.
        self.transport = transport
        self.sock = transport.get_extra_info('socket')
        self.remote_tup = self.sock.getpeername()
        self.client_proto = BaseProto(
            sock=self.sock,
            route=self.proto.route,
            conf=self.conf,
            loop=self.loop
        )

        # Setup stream object.
        self.client_proto.set_endpoint_type(TYPE_TCP_CLIENT)
        self.client_proto.msg_cbs = self.proto.msg_cbs
        self.client_proto.end_cbs = self.proto.end_cbs
        self.client_proto.connection_made(transport)

        # Record destination.
        self.client_proto.stream.set_dest_tup(self.remote_tup)

        # Record instance to allow cleanup in server.
        self.proto.add_tcp_client(self.client_proto)

        # Setup handle for writing.
        super().connection_made(transport)
        self.client_proto.stream.set_handle(
            self._stream_writer,

            # Index writers by peer connection.
            self.remote_tup
        )

    # If close was called on a pipe on a server then clients will already be closed.
    # So this code will have no effect.
    def connection_lost(self, exc):
        # Remove this as an object to close and manage in the server.
        super().connection_lost(exc)

        # Run disconnect handlers if any set.
        client_tup = self.remote_tup
        self.client_proto.run_handlers(self.client_proto.end_cbs, client_tup)

        # Close its client socket and transport.
        try:
            if self.client_proto in self.proto.tcp_clients:
                self.proto.tcp_clients.remove(self.client_proto)
        except Exception:
            log_exception()

        try:
            self.transport.close()
            self.transport = None
        except Exception:
            log_exception()

    def data_received(self, data):
        # This just adds data to reader which we are handling ourselves.
        #super().connection_lost(exc)
        log(f"Hacked server recv = {data}")
        if self.client_proto is None:
            log(f"CLIENT PROTO NONE")
            return

        if not len(self.client_proto.msg_cbs):
            log("No msg cbs registered for inbound message in hacked tcp server.")

        self.client_proto.handle_data(data, self.remote_tup)

# Returns a hacked TCP server object
async def base_start_server(sock, base_proto, *, loop=None, conf=NET_CONF, **kwds):
    # Main vars.
    loop = loop or asyncio.get_event_loop()
    def factory():
        reader = asyncio.StreamReader(limit=conf["reader_limit"], loop=loop)
        return BaseStreamReaderProto(
            reader,
            base_proto,
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
async def pipe_open(route, proto, dest=None, sock=None, msg_cb=None, conf=NET_CONF):
    base_proto = None
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

            # Check if sock succeeded.
            if sock is None:
                log("Could not allocate socket.")
                return None

            # Connect socket if TCP.
            if proto == TCP and dest is not None:
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

        # Return the sock instead of base proto.
        if conf["sock_only"]:
            return sock

        # Main protocol instance for routing messages.
        #if base_proto is None:
        base_proto = BaseProto(sock=sock, route=route, loop=loop, conf=conf)

        # Add message handler.
        if msg_cb is not None:
            base_proto.add_msg_cb(msg_cb)

        # Start processing messages for UDP.
        if proto in [UDP, RUDP]:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: base_proto,
                sock=sock
            )

            await base_proto.stream_ready.wait()
            base_proto.stream.set_handle(transport, client_tup=None)
            if dest is not None:
                base_proto.set_endpoint_type(TYPE_UDP_CON)
            else:
                base_proto.set_endpoint_type(TYPE_UDP_SERVER)

        # Install default ack builder and handler.
        # Now it is poorman's TCP ;_____; but still no ordering.
        if proto == RUDP:
            base_proto.set_ack_handlers(
                is_ack=base_proto.stream.is_ack,
                is_ackable=base_proto.stream.is_ackable
            )

        # Start processing messages for TCP.
        if proto == TCP:
            # Listen server.
            if dest is None:
                # Start router for TCP messages.
                server = await base_start_server(
                    sock=sock,
                    base_proto=base_proto,
                    loop=loop,
                    conf=conf
                )

                # Make the server start serving requests.
                assert(server is not None)
                base_proto.set_tcp_server(server)

                # Saving the task is apparently needed
                # or the garbage collector could close it.
                if hasattr(server, "serve_forever"):
                    server_task = asyncio.create_task(server.serve_forever())
                    base_proto.set_tcp_server_task(server_task)
                base_proto.set_endpoint_type(TYPE_TCP_SERVER)

            # Single connection.
            if dest is not None:
                # base_proto.set_handle(writer, sock.getpeername())
                await loop.create_connection(
                    protocol_factory=lambda: base_proto,
                    sock=sock
                )

                # Set transport handle.
                await base_proto.stream_ready.wait()
                base_proto.stream.set_handle(base_proto.transport, dest.tup)
                base_proto.set_endpoint_type(TYPE_TCP_CON)

        # Set dest if it's present.
        if dest is not None:
            base_proto.stream.set_dest_tup(dest.tup)

        # Register pipes, msg callbacks, and subscriptions.
        return base_proto

    # Timeouts, Connection failures, network changes, etc.
    except asyncio.TimeoutError:
        # Boring, ignore.
        pass
    except Exception as e:
        log_exception()
        if conf["no_close"] == False:
            log("no close is false so trying to clean up.")
            if sock is not None:
                sock.close()
            if base_proto is not None:
                await base_proto.close()

if __name__ == "__main__": # pragma: no cover
    from .interface import Interface
    from .http_client import http_req
    from .address import Address
    async def test_base():
        af = IP4; proto = TCP; port = 10101
        interface = await Interface("enp3s0").start()
        route = await interface.route(af).bind(port)

        """
        TCP server works.
        # A transport router for TCP.
        # Spawms a new stream reader protocol per con.
        base_proto = await transport_router(
            route=route,
            proto=proto
        )
        """

        dest_addr = await Address("127.0.0.1", 12344).res(route)
        base_proto = await pipe_open(
            route=route,
            proto=proto,
            dest=dest_addr
        )

        # Simple message callback that prints inbound data and client addr tups.
        base_proto.add_msg_cb(
            # Data, client tup, stream, route
            lambda d, c, s: print(d, c)
        )

        # Build HTTP req and send to Google con writer.
        get_req = http_req(dest_addr)
        await base_proto.stream.send(get_req, dest_addr.tup)

        # Don't close the main coroutine.
        while 1:
            await asyncio.sleep(1)

    async_test(test_base)