The problem with P2P networking
================================

In peer-to-peer networking one of the most basic problems is getting
two computers to connect to each other. The problem is regular people's
networks aren't designed around the use of servers. They most often
use routers that employ NAT to control connections to the
the network. The router needs to be configured to forward connections
to the right machines -- a process called 'port forwarding.'

Sometimes, port forwarding can be done automatically. Protocols like **UPnP**
and **NATPMP** allow programs to setup such rules.
But in practice the availability of these features is not guaranteed.
If you've ever tried to host a server in an online game you will know this
experience painfully. The game will have tried to port forward automatically.
The trouble is port forwarding can be seen as a security risk and
disabled by default. Plus, it doesn't work for complex networks behind
multiple NATs (often the case on mobile devices.)

Peer-to-peer connections are hard to do reliably because of the many 
network configurations, software platforms, and obstacles that
need be traversed. It's for this reason most successful
P2P systems don't solve this problem directly. Take Bitcoin, for example.
In Bitcoin what matters is that you can connect to someone to download
blocks. Or what about torrents? A swarm of nodes can still download
if some of the peers are reachable. In other words: **these systems don't require
reachability between every node** to function. But some systems do.

Suppose I'm trying to build a chat program and I'd like for people to share files? In this case: I need both parties to be able to connect
directly. Any single method to achieve this (like port forwarding) is not going to
work consistently. The approach taken by P2PD is to combine multiple strategies for 
achieving connectivity to greatly improve the odds of success.

In the next section I will explain :doc:`how`