The problem with P2P networking
================================

In peer-to-peer networking one of the most basic problems is to get
two computers to connect to each other. The problem is regular people's
computers aren't designed to be used as servers. They are most often
behind a router that employs NAT to control which connections can reach
the internal network. The router must be configured to forward connections
to the right machines -- a process called 'port forwarding.'

Sometimes, port forwarding can be done automatically. Protocols like UPnP
and NATPMP allow programs to request a router to setup such rules.
But in practice the availability of these features is not guaranteed.
If you've ever tried to host a server in an online game you will know this
experience painfully. The game will have tried UPnP or NATPMP to port forward.
The trouble is that these features can be seen as a security risk and
disabled by default. And they don't work for more complex networks behind
multiple NATs (easily possible with mobile networking.)

Peer-to-peer connections are hard to do because of the number of
possible network configurations, software platforms, and obstacles that
need be traversed to do it reliably. It's for this reason that the most successful
P2P systems don't solve this problem directly. Take Bitcoin, for example.
In Bitcoin what matters is that you can at least connect to someone to download
blocks. Or what about torrents? A swarm of nodes can still download chunks
if some of the peers are reachable. In other words: these systems don't require
direct reachability between every node to function. But there are systems that do.

Suppose I'm trying to build a chat program and I'd like two people to
be able to share files? In this case: I need both parties to be able to connect
directly. Any single method to achieve this (like port forwarding) is prone to
failure. The approach taken by P2PD is to combine multiple strategies for 
achieving connectivity to greatly improve the odds of success.

In the next section I will explain :doc:`how`