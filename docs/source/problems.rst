The problem with P2P networking
================================

In peer-to-peer networking one of the most basic problems is trying to get
two computers to connect to each other. The problem is that regular
people's computers aren't designed to be used as servers. They are
most often behind a router that employs NAT to control which
connections can reach devices in the internal network. The router must
be specifically configured to forward connections to the right machines --
a process called 'port forwarding.'

Sometimes port forwarding can be done automatically. Protocols like UPnP
and NATPMP allow programs to request a router to setup rules on its behalf.
But in practice the availability of these features is not guaranteed.
If you've ever tried to host a server in an online game before you will know this
first hand. The software will have tried to use UPnP or NATPMP to port forward
your server so that others can reach it. The trouble is that these features
can be seen as a security risk and disabled by default.

Peer-to-peer direct connectivity is hard to do because of the number of
possible network configurations, software platforms, and obstactles that
must be bypassed to do it reliabily. It's for this reason that the most successful
P2P systems don't actually solve this problem. Take Bitcoin, for example.
In Bitcoin what matters is that you can at least connect to someone to download
blocks and broadcast transactions. Or what about torrents? A swarm of nodes can
download chunks of data and spread them between them. In other words:
these systems don't require direct connectivity to every potential node
for them to function. But what about the systems that do?

What if I'm trying to build a chat client and I'd like for two people to
be able to share files between them? In this case I need both parties to be
able to connect directly to each other. I have already spoken about how relying
on a single method like port forwarding is prone to failure. The approach taken
by P2PD is to combine multiple techniques for bypassing NATs and firewalls into
one methodology which greatly improves the chances of success.

In the next section I will explain :doc:`how`