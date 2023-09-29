Toxiproxy client and server
=============================

When it comes to network programming so much of the process is temperamental. 
What I mean by this is the way algorithms perform ultimately ends up
being decided by changing network conditions. If we are to write good
network code there is a need to be able to write algorithms that can
handle many common and unexpected scenarios. But how should one do this?


One cannot simply test their code on the Internet or loopback and hope
for the best. This does not lead to a reliable or systematic approach.
What is needed is a way to model adverse network conditions. So that we
may test how our algorithms deal with unexpected events. One such design
that seems ideally suited for this is Toxiproxy by Shopify.

Toxiproxy
^^^^^^^^^^^^

Toxiproxy consists of a main REST server that spawns sub-servers or tunnels
that are used as relays to different target machines. You can modify behaviors in
these relays - allowing you to test everything from latency to packet recombination algorithms.

Toxiproxy refers to the start of the relay (you) as the **downstream**
while the point that the relay connects to is called the **upstream**.
The algorithms that induce various network behaviors it calls **toxics.**
For example: you can spawn a tunnel server with example.com as the upstream
and set a latency toxic on the upstream (to delay replies back to you.)

The design of Toxiproxy can be used from any programming language because
it's simply a REST API and then custom TCP daemons. Shopify's implementation
is written in Go with many clients available in different programming languages.
However, what I've found is that the client available for Python was incomplete;
wasn't async; and there was no server implementation.

It is much easier to include Toxiproxy for testing Python network code if
you don't also have to figure out how to package a Go server. So P2PD now
includes both a Toxiproxy server and client.

Adding a toxic
^^^^^^^^^^^^^^^^^

Let's start with an example that shows how to add a toxic.

.. literalinclude:: ../python/examples/example_17.py
    :language: python3

So what's going on here? Well, you've started a toxiproxy server and
made a new toxiproxy client that has connected to it. You've created
a new tunnel (spawning a new port to connect to) which connects to
example.com as it's 'upstream' location.

You can control what 'toxics' are active on this tunnel server. Allowing
you to set direction (is it upstream or downstream), probability of activation
(also known as 'toxicity'), and much more. If you send a HTTP request down
'pipe' you will now get a delayed response due to the latency toxic.

I have added support for the toxics specified by Shopify.


