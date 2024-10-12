Pipes
======

In P2PD all messages are sent and received via pipes. Pipes are simply the
name given to the object providing a common list of functions for transmission
and message processing. A pipe supports UDP or TCP; IPv4 or IPv6; and can
be used for clients or servers.

.. code-block:: python

    async def pipe_open(proto, dest=None, route=None, sock=None, msg_cb=None, up_cb=None, conf=NET_CONF):
        """
        proto  = TCP or UDP.
        dest   = If it's a client pipe a destination should be included.
                ('host/ip', port)
                A server includes no destination - None
        route  = Route object that's been bound with await route.bind().
        sock   = Used to wrap a pre-existing socket in a pipe. If the protocol is
                TCP and dest is included the socket is assumed to be connected.
        msb_cb = A message handler registered with servers before they're started
                so that messages aren't received before a handler is setup.
        up_cb  = A handler is started when the underlying pipe is connected.
        conf  = A dictionary describing many different configuration options for
                changing various properties of the pipe.

        More details on msg_cb format and conf format later.
        Returns: a pipe object.
        """

Whether a pipe is for a client or server, UDP or TCP, IPv4 or IPv6, every
pipe works the same. Pipes are able to queue messages or process them as they arrive.
They pass such messages to any handlers (to process in real-time)
or add them to a message queue (to be processed later).

Interface selection
----------------------

In network programming its very common to write code that doesn't manually
choose a network interface. The reason for this is arguably because its hard
to do; If you don't specify an interface the code will still work. But you'll
have to be fine using the default chosen by the OS.

For some applications this is fine. Maybe the only thing that matters is
whether the code works. But other applications might want to be more nuanced.
Imagine a server that has multiple interfaces and it wants to select what ones
to listen on. Or perhaps a torrent client that wants to work across interfaces
(and Internet connections) to increase download speed.

.. IMPORTANT::
    Normally in P2PD you would choose an interface and a route to use for a pipe.
    But to simplify these examples no route is given. In which case -- the
    default interface is loaded for each pipe. This is very inefficient as
    STUN will lookup external addressing each time! 

TCP echo server example
------------------------

Starts a simple TCP server that writes back received data down the client
pipes for the sender. If this example works you should see nothing.
Notice that msg handlers include a field for the senders addressing information
and a pipe that can be used to interact with that client.

.. literalinclude:: ../../examples/example_5.py
    :language: python3

UDP await example
------------------

In Python if you want to do asynchronous networking you normally
have to write different code for UDP and TCP. Python has decent enough
classes for TCP clients (stream readers) -- though UDP has no such equivalent. 
As for servers Python offers protocol classes. Wouldn't it be great if you
could use either style on either protocol?

Here's an example of how simple P2PD makes this. Here I'm using await for UDP
which is based on message queues. Since there is no delivery guarantees for UDP it's
possible this example throws a timeout error for you. Note that the await for
the recv is fully asynchronous. The event loop is free to run other tasks
until a message is received.

.. literalinclude:: ../../examples/example_6.py
    :language: python3

Pipe methods
--------------

Pipes are an instance of the PipeEvents class that provides many useful methods
and properties for working with connections (TCP or UDP.) Assume all of
these methods are of the form 'pipe.method_name()' and that they 'belong'
to a PipeEvents class instance.

----

def add_msg_cb(self, msg_cb)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When a pipe receives a message it will also forward it to any installed message
handlers.

.. TIP::
    async def msg_cb(msg, client_tup, pipe)

The msg_cb also doesn't have to be an async callback but keep in mind if it's
given as a regular function you will have to use asyncio.create_task
to schedule any callbacks and you won't be able to await them. Since
the whole library uses async await it's best to use an async method.

Using message handlers like this is useful because you can install them
for either a server pipe or a client pipe and it will automatically be
called when there's a new message. No need to run your own loop and
call await on them The event loop handles it.

----

def del_msg_cb(self, msg_cb)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Removes a function reference designated by msg_cb from the pipe's msg_cbs.

----

def add_end_cb(self, end_cb)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When a connection is closed manually or forcefully the end_cb handlers are
called. 

.. TIP::
    async def end_cb(msg, client_tup, pipe)

Where message is set to None.

----

def del_end_cb(self, end_cb)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Removes a function reference designated by end_cb from the pipe's end_cb handlers.

----

def add_pipe(self, pipe)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pipes can be made to route messages to other pipes.

.. code-block:: python

    pipe_a.add_pipe(pipe_b)
    pipe_b.add_pipe(pipe_a)

1.  Messages received at pipe_a will be sent down pipe_b.
2.  Messages received at pipe_b will be sent down pipe_a.

This doesn't cause looping as the messages get sent to the destination rather than the pipe itself.
Linking pipes together is the trick used in the P2PD REST API for 'converting' an
active HTTP connection into a two-way relay to an active P2P connection in
only two lines of code.

----

def del_pipe(self, pipe)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unlink 'pipe' from self.

----

async def close(self)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Closes all resources associated with a pipe. If it's a server it will stop serving
any clients and all client connections will be closed. All sockets will be
closed forcefully. Server's that immediately reuse the same port may experience
errors where they fail to receive designated packets. There may be a solution to
this by setting SO_LINGER to enabled and using a zero timeout. But using
this option on client TCP sockets on Windows prevents the hole punching algorithm
from working so this needs to only be considered for server sockets.

----

Additional pipe options
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A default dictionary of configuration options is passed to each pipe. The
options look like this:

.. code-block:: python

    NET_CONF = {
        # Seconds to use for a DNS request before timeout exception.
        "dns_timeout": 2,

        # Wrap socket with SSL.
        "use_ssl": 0,

        # Timeout for SSL handshake.
        "ssl_handshake": 4,

        # Protocol family used for the socket.socket function.
        "sock_proto": 0,

        # N seconds before a registering recv timeout.
        "recv_timeout": 2,

        # Only applies to TCP.
        "con_timeout": 2,

        # No of messages to receive per subscription.
        "max_qsize": 0,

        # Require unique messages or not.
        "enable_msg_ids": 0,

        # Number of message IDs to keep around.
        "max_msg_ids": 1000,

        # Reuse address tuple for bind() socket call.
        "reuse_addr": False,

        # Setup socket as a broadcast socket.
        "broadcast": False,

        # Buf size for asyncio.StreamReader.
        "reader_limit": 2 ** 16,

        # Return the sock instead of the base proto.
        "sock_only": False,

        # Enable closing sock on error.
        "do_close": True,

        # Whether to set SO_LINGER. None = off.
        # Non-none = linger value.
        "linger": None,

        # Retry N times on reply timeout.
        "send_retry": 2,

        # Ref to an event loop.
        "loop": None
    }

    # Here's where to use these options.
    pipe = pipe_open(TCP, route, dest, conf=NET_CONF)