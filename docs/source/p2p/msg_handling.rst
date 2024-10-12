Message handling 
=====================

Message handling is how you will transfer and process data for your protocol.
For these tasks it's helpful to know that everything in P2PD is a pipe
with the same features. A 'connection' is a pipe with a set destination.
A 'server' is a pipe with no set destination. Pipes support both callbacks
and async-await -- or mixing them if you choose.

First lets look at callbacks. Callbacks get a bad rep because people find them
confusing but they're very convenient for servers because
they will run only when you get a message. It's then a nice tidy way to write
a protocol instead of writing a recv loop yourself.

.. literalinclude:: ../../examples/p2pd_in_a_nutshell.py
    :language: python3

The **pipe** parameter refers to a TCP client connection
(if the server pipe was TCP) or a single, multiplexed UDP pipe (if the server pipe
was UDP.) This also explains why there's a **client_tup** parameter: a multiplexed,
UDP socket is connectionless and can be reused for many destinations. So by specifying a
destination it makes server code compatible with TCP and UDP.

Let's look at async-await now.


.. literalinclude:: ../../examples/p2p_tcp_con.py
    :language: python3

The async-await socket functions are non-blocking and won't stall your program
dealing with I/O. As expected, once they are done, your surrounding code can
continue where it left off. Simulating the control flow of a regular program.
The next section cover general networking with P2PD more in depth. It's
recommended to at least read the first section.