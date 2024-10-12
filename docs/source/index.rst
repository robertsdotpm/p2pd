Documentation
====================

Have you ever tried to connect to a computer and it didn't work? Look no further.
P2PD is a library designed to make it easier for developers to establish
peer-to-peer TCP connections. It handles all of the complexity of modern
networks such as NAT traversal and firewalls. So you can
focus on building your software instead of traversing NATs (fun times.)

.. literalinclude:: ../examples/p2pd_in_a_nutshell.py
   :language: python3

In P2PD nodes have long addresses to describe their network details. The
address includes information like external IPs and NAT types. But
just as its inconvenient to use IPs directly its inconvenient
to use addresses directly. So instead a nickname can be registered for the
address. When you give your node a nickname you can give it out to other
peers to connect to.

**This service is free and requires no registration in P2PD.**

.. literalinclude:: ../examples/p2p_connect_with_nickname.py
   :language: python3

Before we get ahead of ourselves though: the nickname you register isn't the
full name you need to give out to others. This is because a TLD is appended
to it after registration that identifies the quorum of name servers that
can be used to pull records from your name. So it's important you give
out the full name. Ready to learn more?

.. toctree::
   p2p/index
   general/index
   articles/index
   built/index
   dev/index

