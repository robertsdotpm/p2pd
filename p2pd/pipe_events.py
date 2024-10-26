"""
Python's asyncio protocol classes seem to return human-readable
tuples that identify the packet's sender. At first glance this
seems to make sense. For people use the readable form of
addresses when working with them. But the network stack
needs it in binary form for routing. Hence, it will end up
having to convert an address to/from binary.

The problem is more complicated because IPv6 can have several representations of the same address in a readable form.
E.g. omitting zero portions with : or leading zero parts
of a segment. If you're trying to index a reply by an address it adds extra work because you have to normalize the address (for IPv6.)
Extra work means extra CPU.

Networking is generally supposed to be as fast as possible so
this design might not be ideal.
"""

import asyncio
from .utils import *
from .net import *
from .ack_udp import *
from .pipe_client import *

TYPE_UDP_CON = 1
TYPE_UDP_SERVER = 2
TYPE_TCP_CON = 3
TYPE_TCP_SERVER = 4
TYPE_TCP_CLIENT = 5

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
class PipeEvents(BaseACKProto):
    def __init__(self, sock, route=None, loop=None, conf=NET_CONF):
        super().__init__(conf)

        # Config.
        self.conf = conf
        self.loop = loop

        # Socket of underlying connection.
        self.client_tup = None
        self.sock = sock
        self.tcp_clients = []
        self.tcp_server = None
        self.tcp_server_task = None
        self.endpoint_type = None

        # Used for TCP server awaitable.
        self.p_client_entry = 0 # Location of the pipe in client futures.
        self.p_client_insert = 0 # Last insert location in client futures.
        self.p_client_get = 0 # Offset that increases per await over the futures.
        self.client_futures = { 0: asyncio.Future() } # Table for TCP client pipes.

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

        # Ran when a connection is made.
        # For TCP this is a new connection.
        self.up_cbs = []

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
        self.proc_lock = None

    # Indicates the type of endpoint this is.
    def set_endpoint_type(self, endpoint_type):
        self.endpoint_type = endpoint_type

    # Used for event-based programming.
    # Can execute code on new cons, dropped cons, and new msgs.
    def run_handlers(self, handlers, client_tup=None, data=None):
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
        # Save location of this client pipe in the table.
        client.p_client_entry = self.p_client_insert

        # Point to next entry in table and initialize it.
        self.p_client_insert = (self.p_client_insert + 1) % sys.maxsize
        self.client_futures[self.p_client_insert] = asyncio.Future()

        # Store this pipe in the Future.
        self.tcp_clients.append(client)
        self.client_futures[client.p_client_entry].set_result(client)

    async def make_awaitable(self):
        if self.endpoint_type == TYPE_TCP_SERVER:
            bound = self.p_client_insert + 1
            for p in range(0, bound):
                # Get reference to the current future to await on.
                cur_p_get = (self.p_client_get + p) % bound

                # Skip empty entries deleted on connection lost.
                if self.client_futures[cur_p_get] is None:
                    continue

                # Increment the pointer to the next future in line.
                # This sets it up for the next await call to work.
                # Only increment it if the current location is taken.
                if self.client_futures[cur_p_get].done():
                    self.p_client_get = (cur_p_get + 1) % bound

                # Await on the future at the head of the futures.
                return await self.client_futures[cur_p_get]

            raise Exception("Could not find awaitable future accept().")
        else:
            # TCP con -> one pipe so no reason to await it.
            # UDP server or con -> multiplex so one pipe for everything.
            return self

    def __await__(self):
        return self.make_awaitable().__await__()

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
    
    def add_up_cb(self, up_cb):
        self.up_cbs.append(up_cb)
        return self

    def del_up_cb_cb(self, up_cb):
        if up_cb in self.up_cbs:
            self.up_cbs.remove(up_cb)

        return self

    def add_end_cb(self, end_cb):
        self.end_cbs.append(end_cb)

        # Make sure it runs if this is already closed.
        if not self.is_running:
            self.run_handlers(end_cb)

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
                self.client_tup = self.get_client_tup()

            # Set stream object for doing I/O.
            self.stream = PipeClient(self, loop=self.loop)
            self.stream_ready.set()

        # Process messages using any registered handlers.
        self.run_handlers(self.up_cbs)

    # Socket closed manually or shutdown by other side.
    def connection_lost(self, exc):
        super().connection_lost(exc)

        # Remove self from any parent pipes.
        for pipe in self.parent_pipes:
            pipe.del_pipe(self)
        
        # Execute any cleanup handlers.
        self.run_handlers(self.end_cbs, self.client_tup)

    def route_msg(self, data, client_tup):
        # No data to route.
        if not data:
            return

        # Route messages to any pipes.
        for pipe in self.pipes:
            task = create_task(
                pipe.send(
                    data,
                    pipe.sock.getpeername()
                )
            )

            self.tasks.append(task)

        # Process messages using any registered handlers.
        self.run_handlers(self.msg_cbs, client_tup, data)

        # Add message to any interested subscriptions.
        # Matching pattern for host is in bytes so
        # there is a need to convert ip to bytes.
        self.stream.add_msg(
            data,
            (client_tup[0], client_tup[1])
        )

    def handle_data(self, data, client_tup):
        # Convert data to bytes.
        if isinstance(data, bytearray):
            data = bytes(data)

        # Norm IP.
        client_tup = norm_client_tup(client_tup)

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
                return

        # Route message to stream.
        self.route_msg(data, client_tup)

    def error_received(self, exp):
        log(str(exp))
        pass

    # UDP packets.
    def datagram_received(self, data, client_tup):
        #log(f"Base proto recv udp = {client_tup} {data}")
        if self.transport is None:
            log(f"Skipping process data cause transport none 1.")
            return

        self.handle_data(data, client_tup)

    # Single TCP connection.
    def data_received(self, data):
        try:
            #log(f"Base proto recv tcp = {data}")
            if self.transport is None:
                log(f"Skipping process data cause transport none 2.")
                return

            client_tup = self.transport.get_extra_info('socket').getpeername()
            self.handle_data(
                data,
                client_tup
            )
        except:
            log_exception()

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
        #self.tasks = rm_done_tasks(self.tasks)
        self.tasks = []
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
            if client.close != self.close:
                await client.close(do_sleep=False)

        # Close the main server socket.
        # This does cleanup for any TCP servers.
        if self.transport is not None:
            self.transport.close()

        """
        if self.tcp_server_task is not None:
            self.tcp_server_task.cancel()
        """

        # Close any sockets.
        # if self.sock is not None:
        #    self.sock.close()
        
        # No longer running.
        self.transport = None
        self.socket = None
        self.is_running = False
        self.tcp_server = None
        self.tcp_server_task = None
        self.tcp_clients = []
        if self.proc_lock is not None:
            self.proc_lock.release()

    # Return a matching message, async, non-blocking.
    async def recv(self, sub=SUB_ALL, timeout=2, full=False):
        return await self.stream.recv(sub, timeout, full)

    async def send(self, data, dest_tup=None):
        dest_tup = dest_tup or self.stream.dest_tup
        return await self.stream.send(data, dest_tup)

    # Sync subscribe to a message.
    # Easy way to get a message from sync code too.
    def subscribe(self, sub=SUB_ALL, handler=None):
        return self.stream.subscribe(sub, handler)

    def unsubscribe(self, sub):
        return self.stream.unsubscribe(sub)

    # Echo client just for testing.
    async def echo(self, msg, dest_tup):
        buf = bytearray().join([b"ECHO ", msg, b"\n"])
        await self.send(buf, dest_tup)

