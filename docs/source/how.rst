How P2PD works
===============

Adressesses
------------

In P2PD it all starts with the address. You may already be familar with IPv4
and IPv6 addresses. Such addresses allow for data to reach nodes on
the packet-switched network we call the Internet. Practically we can say that
these addresses are assigned to routers. They work quite well for regular
servers but in a peer-to-peer context much more information is needed to
describe a peer's network setup. Here is what a peer's address looks like.

``0,1-[0,8.8.8.8,192.168.21.21,58959,3,2,0]-0-zmUGXPOFxUBuToh``

As you can see there are already pieces of information you may recognize.
There is an IPv4 address and a private LAN IP that belongs to the NIC
interface associated with that external IP. But what is the other information?
Well, the address format includes the following details.

-   **Signaling offsets.** Peers include a list of offsets for the MQTT
    servers to use in the settings file for signaling messages.
-   **Interface offset.** Peers include a list of interfaces to listen on. 
    The interface offset is referenced in protocol messages so the correct
    interface is used.
-   **External IP.** The WAN IP associated with a given interface route.
-   **Internal IP.** The private address associated with a route. For IPv6
    this field will include a link local address. For IPv4 this will
    be a specific IP for the NIC.
-   **Listen port.** The port used to listen on by the peer's main server.
-   **NAT type.** The main type of NAT if the router for a route.
-   **Delta type.** Information on a NAT's port mapping logic.
-   **Delta value.** Information on any patterns found in a NAT's port mappings.
-   **Node ID.** A random identifier assigned to the node. The identifier is
    subscribed to in MQTT to receive signal messages. More on this later.

The address format can describe multiple interfaces and address families.
The maximum interface number is currently limited to 3 per address family.
The importance of these addresses is they are what's used to open direct
connections to a given peer. You will need to think about the best way to get
these addresses when writing software. For example: are you going to assume
people will give each other their addresses over a chat program? The
next section will give you a better idea.

Signaling
----------

P2PD uses the MQTT protocol for signaling messages. Signaling messages
refer to messages P2PD uses to coordinate connections between peers. Some
examples of such messages include:

-   **P2P_DIRECT** = Tell a peer to connect back to an address.
-   **ECHO** = Tell a peer to echo back data sent to it. Very useful for
    testing whether a system actually works!
-   **INITIAL_MAPPINGS** = Exchange predicted port mappings as part of the
    sequence of events leading up to TCP hole punching.

Signaling messages are instrumental to the workings of P2PD. By relying on
public, open, MQTT servers messages are able to reach peers directly without
the cumbersome restrictions of a NAT. The way this occurs is through the
use of random IDs as topic subscriptions. A peer subscribes to a random ID
and includes this ID in its address information. Messages can then reach that
peer via an MQTT broker server. Such an approach is scalable and already
has a wide variety of public infrastructure.

You may be more familar with Bitcoin and how it initially used IRC
to connect to its peer-to-peer network. What Bitcoin was doing was using
IRC as a 'pub-sub' system. Specific channels were marked topics to subscribe to.
Then the rooms were joined and channel members served as public entry points
to the Bitcoin peer-to-peer network.

MQTT can be used in the same way. As a publish-subscribe system. But
it's actually built for the purpose. Making it easier to use, more scalable,
and far less hacky.

Methodology
------------

P2PD uses 4 different strategies to try establish a connection between peers.

**1. Direct Connect**

If a peer has successfully port forwarded their main server then a regular TCP connection can be openned. There is nothing special about this.

**2. Reverse Connect**

In peer-to-peer connections both sides run a server. Therefore: a connection
can be established if A connects to B or vice-versa. Reverse connect tells
a peer to connect back to the node sending the request. This means that
connectivity is successful if either one of two peers wishing to
connect has been able to port forward.

**3. TCP Hole Punching**

There is a little known feature of TCP that allows for a connection to
be openned if two sides connect to each other at the same time. You may
be familar with a process called the 'SYN three-way handshake.' What
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
-----------

Now you have a good understanding how P2PD works. Choose a specialty:

1.  I want to learn :doc:`how to use the P2PD REST API.<rest_api>`
        :doc:`I'm not interested in touching any Python code.<rest_api>`
2.  I want to learn :doc:`how to use P2PD's library in my Python 3 program.<python/basics>`
        :doc:`I think Python is le based so let's use it.<python/basics>`