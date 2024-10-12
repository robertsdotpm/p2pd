Toxiproxy client and server
=============================

Network programming is temperamental. The way algorithms perform is
decided by changing networks. If we are to write good
network code there is a need to write algorithms that can handle common
and unexpected scenarios. But how to accomplish this?


One cannot simply test code against the Internet. This does not
lead to a reproducible result. What is needed is a way to
model adverse conditions deterministically. So that we may test how
our algorithms respond in the real world. One such design that seems well
suited for this task is 'Toxiproxy' created by Shopify.

Toxiproxy
^^^^^^^^^^^^

Toxiproxy consists of a REST server that spawns tunnel servers. Each tunnel server
can be used as a relay to a different target machine. You can even modify behaviors
on these relays - allowing you to test everything from latency to packet
recombination algorithms.

Toxiproxy refers to the start of the relay (you) as the **downstream**
while the point the relay connects to is called the **upstream**.
The algorithms that induce network behaviors are termed **toxics.**
For example: you can spawn a tunnel server with example.com as the upstream
and set a latency toxic on the upstream (to delay replies back to you.)

The design of Toxiproxy can be used from any programming language because
it's simply a REST API with custom TCP daemons. Shopify's implementation
is written in Go but many clients are available for different programming languages.
Though: what I've found is their client for Python is incomplete;
isn't async; and has no server implementation.

P2PD now includes an implementation of Toxiproxy server with a client to use it.

Adding a toxic
^^^^^^^^^^^^^^^^^

Let's start with an example that shows how to add a toxic.

.. literalinclude:: ../../examples/example_17.py
    :language: python3

The example starts a new toxiproxy server and connects to it. Then a tunnel is
made (spawning a new port to connect to) which connects to example.com as
the 'upstream' location.

You can control what 'toxics' are active on this tunnel server. Allowing
you to set direction (is it upstream or downstream), probability of activation
(also known as 'toxicity'), and more. If you send a HTTP request down the
'pipe' you will get a delayed response due to the latency toxic.

I have added support for the toxics specified by Shopify. The rest
of these toxics assume calling ToxiToxic().upstream().toxic_name...
or ToxiToxic().downstream().toxic_name.

add_latency(ms, jitter)
^^^^^^^^^^^^^^^^^^^^^^^^^^
Adds N ms of latency with +/- jitter (random inclusive.)

add_bandwidth_limit(kb)
^^^^^^^^^^^^^^^^^^^^^^^^^^^
Adds a limit of kb kilobytes per second.

add_slow_close(ms)
^^^^^^^^^^^^^^^^^^^^^^
Adds a delay to the connection being closed. So even if close is called on a pipe due in the code that coroutine will be delayed.

add_timeout(ms)
^^^^^^^^^^^^^^^^^^^
Prevents data from being forwarded and closes the connection after timeout.
If timeout is set to 0 then the connection won't close and no data will
be delayed on this toxic is removed.

add_reset_peer(ms)
^^^^^^^^^^^^^^^^^^^^^^
Normally when you call close() on a socket it 'gracefully' closes the connection. So that unsent data is sent and it indicates the sender is finished. This toxic instead tears down a connection immediately (ms=0) or after
a timeout. Unsent data will be discarded.

add_limit_data(n)
^^^^^^^^^^^^^^^^^^^^^
Keeps a count of the number of bytes sent. When it reaches n the
connection is closed.

add_slicer(n, v, ug)
^^^^^^^^^^^^^^^^^^^^^^^^
When you call recv on sockets with TCP you may receive some
or all of your data. The slicer takes received data
and splits them up into multiple sends.
Where n is the average byte no of a packet, v is the variation in
bytes of an average packet, and ug is the microseconds to sends by.

There are tests that show usage for all of the above toxics.
See tests/test_toxid.py for an example.

See https://github.com/Shopify/toxiproxy for more information.