Connection strategies
======================

P2PD uses 4 different strategies to try establish a connection between peers.

.. image:: ../../diagrams/connectivity.png
    :alt: Diagram of P2P connectivity methods

**1. Direct Connect**

If a peer has successfully port forwarded their main server then a regular TCP connection can be opened. There is nothing special about this.

**2. Reverse Connect**

In peer-to-peer connections both sides run a server. Therefore: a connection
can be established if A connects to B or vice-versa. Reverse connect tells
a peer to connect back to the node sending the request. This means that
connectivity is successful if either one of two peers wishing to
connect has been able to port forward.

**3. TCP Hole Punching**

There is a little known feature of TCP that allows for a connection to
be opened if two sides connect to each other at the same time. You may
be familiar with a process called the 'SYN three-way handshake.' What
this involves is the exchange of small message flags in order to open
a new TCP connection. It so happens that if two sides connect to each
other at the same time it's possible for these flag packets to arrive
in such a way that it opens a new valid connection. This is *much*
easier said than done.

For TCP hole punching to work certain conditions need to be met.

1.  **Synchronicity** -- Peers need to exchange packets at roughly
    'the same time.' In distributed systems synchronizing peers is known
    to be a very difficult problem. P2PD uses the NTP protocol to achieve
    1 - 30 ms accuracy.
2.  **Latency** -- The closer together two peers are from each other, the
    sooner packets will arrive, and the harder it is to do TCP hole punching.
    If packets in the SYN three-way handshake arrive too soon then
    the NAT can reject it; Latency and synchronicity are important.
3.  **Predictability** -- TCP hole punching relies on the ability to predict
    how a NAT will map the external ports used for outgoing connections.
    Many NAT types are highly predictable. Not all NATs exhibit
    properties that are predictable. These will fail TCP hole punching.
4.  **Restrictiveness** -- Some NATs impose special conditions in order
    for predictability to be preserved. E.G. requiring a certain reply
    port for an inbound connection. Some NATs are too restrictive. They
    will randomize all connections or impose restrictive firewalls.
    
P2PD's TCP hole punching feature has been tested on many different NAT
configurations and operating systems. It can work behind NATs too to
help bypass firewalls within a LAN. It also works inside virtual
machines which seem to impose more restrictions on direct connectivity.
Even so -- TCP hole punching can still fail -- and a last resort is needed.

**4. TURN**

TURN is a protocol that provides a generic proxy service for TCP and
UDP traffic. It is utilized within WebRTC as a last resort approach
for connecting peers when all other connection establishment options have
failed. Since TURN servers must relay all traffic between peers it
is much more expensive and centralized than other options. Hence why TURN
is only used as a last resort.

In P2PD TURN support is not part of the default strategies for P2P connections
as it utilizes UDP instead of TCP which would be inconsistent with other
approaches. The TURN client I have implemented includes a feature
that automatically acknowledges messages and retransmits them.
Though sequencing has not been provided. The client is implemented in
such a way that it provides an identical API to the connections returned
from following any of the above strategies.

Next Steps
------------

Now you have a good understanding how P2PD works. Choose a specialty:

1.  I want to learn :doc:`how to use P2PD's library in my Python 3 program.<python/basics>`
        :doc:`I think Python is le based so let's use it.<python/basics>`
2.  I want to learn :doc:`how to use the P2PD REST API.<rest_api>`
        :doc:`I'm not interested in touching any Python code.<rest_api>`
