TURN client for proxying
==========================

TURN is a protocol used for relaying TCP and UDP between peers.
P2PD implements an asynchronous, IPv4 / IPv6, TURN client.
It has the same interface as a pipe for convenience. But here UDP is the protocol.
To make things easier the software will provide acknowledgements but does not
yet offer ordered delivery.

The reason why UDP was implemented and not TCP is due to the way TCP works and
how TURN was designed to be used. P2PD already implements **direct connect, 
reverse connect, and TCP hole punching**. If all of these fail it means there
is very little chance of establishing a TCP connection with a peer.
Confusingly: this is the assumption made in the TURN protocol. The TURN server
makes an outgoing connection to a service (which must be reachable.)

The TURN spec mentions that this could be combined with **TCP hole punching
for clients**. But since it offers no synchronization method this is not practical.
All of this could have been avoided if TURN were designed around reverse connect.
So that both parties behind NATs could simply connect to the server. But
TURN offers no such feature.

.. TIP::
    When you go through the TURN protocol you get allocated a 'relay address'
    that another peer can use to route messages to you. As far as I know
    this only works for UDP. But importantly it offers a reverse connect
    design which is better for bypassing NATs. 

----

A TURN client example (long)
-------------------------------

.. image:: ../../diagrams/turn_proxy.png
    :alt: Establishing TURN relays

.. literalinclude:: ../../examples/example_10.py
    :language: python3

----

Using TURN as a fall-back option
-----------------------------------

P2PD uses three main strategies to establish a TCP connection. By default TURN
is disabled because it uses UDP. However, it can be enabled easily.

See :ref:`turn relaying <connect-turn-relaying>` for details.