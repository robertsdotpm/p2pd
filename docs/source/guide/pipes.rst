The Pipe API
==============

Every connection in P2PD is a **pipe** — a uniform object that
abstracts over TCP/UDP, IPv4/IPv6, client/server, and even P2P
connections.  If you can open a pipe you can send and receive on it
using the same API regardless of the underlying transport.

----

Opening a pipe
---------------

.. code-block:: python

    pipe = await pipe_open(proto, dest=None, route=None,
                           sock=None, msg_cb=None, up_cb=None,
                           conf=NET_CONF)

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Parameter
     - Meaning
   * - ``proto``
     - ``TCP`` or ``UDP``
   * - ``dest``
     - ``(host, port)`` for client pipes; omit for server pipes.
   * - ``route``
     - A ``Route`` object bound to a specific NIC and source address.
         When omitted the default interface is used (inefficient — STUN
         runs each time).
   * - ``sock``
     - Wrap a pre-existing socket.
   * - ``msg_cb``
     - Callback fired when a message arrives.
   * - ``up_cb``
     - Callback fired when the underlying connection is established.
   * - ``conf``
     - Dictionary of configuration options (see below).

----

TCP echo server (callback style)
-----------------------------------

.. literalinclude:: ../../examples/guide_05_echo_server.py
   :language: python3

**Run it:**

.. parsed-literal::

    python3 docs/examples/guide_05_echo_server.py

The ``msg_cb`` signature is always:

.. code-block:: python

    async def msg_cb(msg, client_tup, pipe):
        ...

``client_tup`` is ``(ip, port)`` of the sender.  For TCP, ``pipe``
is the per-client connection; for UDP it is the shared server socket
(so passing ``client_tup`` to ``pipe.send()`` is how you reply to the
right sender).

----

UDP await (queue style)
-------------------------

.. literalinclude:: ../../examples/guide_06_udp_await.py
   :language: python3

**Run it:**

.. parsed-literal::

    python3 docs/examples/guide_06_udp_await.py

The key point: ``await pipe.recv()`` works for both TCP and UDP.
For UDP it pulls the next datagram from an internal queue, keeping
the event loop free while waiting.

----

Pipe methods
--------------

``pipe.send(data, dest=None)``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Send ``data`` (bytes) down the pipe.  Pass ``dest`` for UDP server
pipes where the socket is shared across many clients.

``await pipe.recv(timeout=None)``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Wait for the next message.  Returns ``None`` on timeout (does not raise).

``pipe.add_msg_cb(cb)`` / ``pipe.del_msg_cb(cb)``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Install or remove a message callback.  Multiple callbacks can be
registered; all fire on each message.

``pipe.add_end_cb(cb)`` / ``pipe.del_end_cb(cb)``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Install or remove a close callback.  ``msg`` is ``None`` when called.

``pipe.add_pipe(other)``
^^^^^^^^^^^^^^^^^^^^^^^^^^

Link two pipes so messages received on one are forwarded to the other.
This is how the P2PD REST API converts an HTTP connection into a live
P2P relay in two lines:

.. code-block:: python

    http_pipe.add_pipe(p2p_pipe)
    p2p_pipe.add_pipe(http_pipe)

``await pipe.close()``
^^^^^^^^^^^^^^^^^^^^^^^^

Close all sockets and fire end callbacks.  Use ``async with pipe:``
for automatic cleanup.

----

Configuration options
-----------------------

A ``conf`` dictionary controls per-pipe behaviour.  The defaults are:

.. code-block:: python

    NET_CONF = {
        "dns_timeout":   2,       # DNS lookup timeout (seconds)
        "use_ssl":       0,       # Wrap socket with SSL
        "ssl_handshake": 4,       # SSL handshake timeout
        "recv_timeout":  2,       # recv() timeout
        "con_timeout":   2,       # TCP connect timeout
        "max_qsize":     0,       # Max queued messages (0 = unlimited)
        "enable_msg_ids":0,       # Deduplicate messages by ID
        "max_msg_ids":   1000,    # Number of IDs to remember
        "reuse_addr":    False,   # SO_REUSEADDR on bind()
        "broadcast":     False,   # SO_BROADCAST
        "reader_limit":  2**16,   # asyncio.StreamReader buffer size
        "sock_only":     False,   # Return raw socket instead of pipe
        "do_close":      True,    # Auto-close socket on error
        "linger":        None,    # SO_LINGER value
        "send_retry":    2,       # Retry count on send timeout
        "loop":          None,    # Explicit event loop reference
    }

Customise by creating a child dictionary:

.. code-block:: python

    from p2pd import *

    custom = dict_child({
        "recv_timeout": 10,
        "con_timeout":  5,
    }, NET_CONF)

    pipe = await pipe_open(TCP, dest=("example.com", 80), conf=custom)

.. TIP::
    TCP callbacks in P2PD may contain partial or buffered data.  TCP is
    stream-oriented — one ``send()`` call does not guarantee one
    ``recv()`` call.  Design your protocol with framing (length prefixes
    or delimiters).
