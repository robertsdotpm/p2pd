Pipes
======

In P2PD all data messages are sent and received via pipes. Pipes are simply the
name given to the object providing a common list of functions for transmission
and message processing. A pipe supports UDP or TCP and IPv4 or IPv6.

.. code-block:: python

    async def pipe_open(proto, route, dest=None, sock=None, msg_cb=None, conf=NET_CONF):
        """
        proto = TCP or UDP.
        route = Route object that's been bound with await route.bind().
        dest  = If it's a client pipe a destionation should be included.
                    await Address('host/ip', port, route).res()
                A server includes no destination.
        sock  = Used to wrap a pre-existing socket in a pipe. If the protocol is
                TCP and dest is included the socket is assumed to be connected.
        cb    = A message handler registered with servers before they're started
                so that messages aren't received before a handler is setup.
        conf  = A dictionary describing many different configuration options for
                changing various properties of the pipe.

        More details on msg_cb format and conf format later.

        Returns: a pipe object.
        """

Whether a pipe is for a client or server, UDP or TCP, IPv4 or IPv6, every
pipe works the same. Pipes have been designed to process messages as
they arrive. They pass these messages to any registered
handlers (to process in real-time) or message queues (to be processed later).

TCP echo server example
------------------------

Starts a simple TCP server that writes back received data down the client
pipes for the sender. If this example works you should see nothing.
Notice that msg handlers include a field for the senders addressing information
and a pipe that can be used to interact with that client.

.. literalinclude:: examples/example_5.py
    :language: python3

UDP await example
------------------

In Python if you want to do asynchronous programming you're likely going to be writing different code for TCP and UDP. This is because TCP is 'stream-based' and UDP 
is 'packet-based.' TCP streams are reliable and ordered. UDP communication is not.
So in Python for TCP connections you will be dealing with 'streams' while for
UDP you will use protocol classes.

Only stream readers are 'asynchronous' e.g. you can await 'draining' a writer
or await a reader - while there is no such equivalent for UDP. It's all very
**inconvenient**. Wouldn't it be great if you could use asynchronous awaits
for UDP and TCP? Further: wouldn't it be great if you modelled interactions in
such a way that the same code would work for both?

Here's an example of how simple P2PD makes this. Here I'm using await for UDP
which is based on message queues. Since there is no delivery guarantees for UDP it's
possible this example throws a timeout error for you. Real-world code that deals
with TCP usually has retransmissions built-in after a set duration. But no such
logic here has been included. Note that the await for the recv is fully
asynchronous. The event loop is free to run other tasks until a match occurs.

.. literalinclude:: examples/example_6.py
    :language: python3

Pipe methods
--------------

Pipes are an instance of the BaseProto class that provides many useful methods
and properties for working with connections (TCP or UDP.) Assume all of
these methods are of the form 'pipe.method_name()' and that they 'belong'
to a BaseProto class instance.

def subscribe(self, sub=SUB_ALL, handler=None)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Install a new message queue indexed by the regex pair sub = [msg_regex, client_tup_regex]. Doing this enables the use of publish-subscribe e.g. 
push / pull style awaits for a message. **By default a pipe will subscribe to all messages (SUB_ALL) if a pipe has a destination given.**

.. code-block:: python

    # Match any message containing meow.
    # Allow only hosts from the 192.168.0.0/16 subnet.
    # Put them into the same queue.
    sub = [b"meow", b"192[.]168[.][0-9]+[.][0-9]+:[0-9]+"]
    pipe.subscribe(sub)

    # Wait for a message that fits into the sub queue.
    await pipe.recv(sub, timeout=4)

def unsubscribe(self, sub)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Delete the queue and its resources marked by sub (if it exists.) No longer
copy messages that fit this subscription into this queue.

async def recv(self, sub=SUB_ALL, timeout=2, full=False)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Given a queue identified by the subscription 'sub' -- wait for a message that suites it. Waiting is done asynchronously and other tasks may be done by the
event loop until a message arrives. Timeout specifies the total duration
to attempt to wait. After the duration an exception will be thrown. Set this
to 0 to disable timeouts (not recommended.)

.. code-block:: python

    # Wait for any message from a loopback client.
    out = await pipe.recv([b"[\s\S]+", "127.0.0.1:[0-9]+"])

By default this function only returns the message received on the pipe.
Some pipes receive messages from multiple destinations (like UDP.)
To also show the sender set the full flag to True. The return value will
end up being [msg_bytes, client_tup].

async def send(self, data, dest_tup=None)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Wait for data to be transmitted down the pipe (non-blocking.) For TCP / UDP connections (with a fixed destination) the dest_tup does not need to be set.
But it's a good practice to include it in servers because the same socket
in UDP servers is used to receive messages from multiple clients and the
pipe by itself won't be able to disambiguate what the destination should be.
This is also one reasons why msg_cbs include a client_tup for a message sender.

def add_msg_cb(self, msg_cb)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When a pipe receives a message it will also forward it to any installed message
handlers. The format for a message handler is:
    
    **async def msg_cb(msg, client_tup, pipe)**

The msg_cb also doesn't have to be an async callback but keep in mind if it's
given as a regular function you will have to use asyncio.create_task
to schedule any callbacks and you won't be able to await them. Since
the whole library uses async await it's best just to use an async msg_cb.

Using message handlers like this is very useful because you can install them
for either a server pipe or a client pipe and it will automatically be
called when there's a new message. No need to run your own loop and
call awaits on some object. The event loop handles it.

def del_msg_cb(self, msg_cb)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Removes a function reference designated by msg_cb from the pipe's msg_cbs.

def add_end_cb(self, end_cb)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When a connection is closed manually or forcefully the end_cb handlers are
called. These are useful for cleanup. The format is:
    
    **async def end_cb(msg, client_tup, pipe)**

Where message is set to None.

def del_end_cb(self, end_cb)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Removes a function reference designated by end_cb from the pipe's end_cb handlers.

def add_pipe(self, pipe)
^^^^^^^^^^^^^^^^^^^^^^^^^

Pipes can be made to route messages to other pipes. You can connect
two pipes together by adding each pipe to each other.

.. code-block:: python

    pipe_a.add_pipe(pipe_b)
    pipe_b.add_pipe(pipe_a)

1.  Messages received at pipe_a will be sent down pipe_b.
2.  Messages received at pipe_b will be sent down pipe_a.

This doesn't cause looping as the messages get sent to the destination rather than the pipe itself. Linking pipes together is the trick used in the P2PD REST API
for 'converting' an active HTTP connection into a two-way relay to an active P2P connection in only two lines of code.

def del_pipe(self, pipe)
^^^^^^^^^^^^^^^^^^^^^^^^^

Unlink 'pipe' from self.

async def close(self)
^^^^^^^^^^^^^^^^^^^^^^^

Closes all resources associated with a pipe. If it's a server it will stop serving
any clients and all client connections will be closed. All sockets will be
closed forcefully. Server's that immediately reuse the same port may experience
errors where they fail to receive designated packets. There may be a solution to
this by setting SO_LINGER to enabled and using a zero timeout. But using
this option on client TCP sockets on Windows prevents the hole punching algorithm
from working so this needs to only be considered for server sockets.

Additional pipe options
---------------------------

A default dictionary of configuration options is passed to each pipe. The
options look like this:

.. code-block:: python

    NET_CONF = {
        # Only applies to TCP.
        "con_timeout": 2,

        # No of messages to receive per subscription.
        "max_qsize": 1000,

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

        # Disable closing sock on error.
        "no_close": False,

        # Whether to set SO_LINGER. None = off.
        # Non-none = linger value.
        "linger": None,

        # Ref to an event loop builder.
        "loop": None
    }

    # Here's where to use these options.
    pipe = pipe_open(TCP, route, dest, conf=NET_CONF)