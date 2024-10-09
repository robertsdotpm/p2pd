NAT prediction
=========================

NAT types
-----------

Home routers use NATs that dynamically create rules for the entry of
traffic into the network. The rules state that for an external port (a mapping)
redirect traffic back to a machine in the network. The NAT may have additional
criterial like whether traffic should come from a certain IP or port. The exact criteria will depend on the **NAT type.**

The algorithm for determining the NAT type of a router is implemented by
testing which packets can make it back from a STUN bind request based
on requesting replies from differing IPs and ports. You start by testing
for the least restrictive to most restrictive NAT. This acts like a sieve,
eventually arriving at the least restrictive possible NAT for the router.

Knowing the NAT type is very useful as it indicates how to reuse mappings. But what about NATs that have fixed IP requirements for inbound packets? If you look up a
mapping using a STUN server then the router will require only packets
from that IP can use the mapping. Fortunately, there is another trick we can use.
The **delta type**.

.. csv-table::
    :file: ../../diagrams/nat_characteristics.csv
    :header-rows: 1

----

Delta types
---------------

Delta type refers to the algorithm used by the router to choose an external port
to use as a mapping. Some delta types have the much desired quality of being
predictable. In fact 'equal' delta types will try to preserve the source port
use by a LAN client for an external mapping. In peer-to-peer networking knowing
the delta type gives us another tool to work with NAT implementations. A predictable
delta means being able able to create openings through the NAT.

Depending on the type of delta there may also be a delta value. E.g. its common
for mappings to simply increase by 1 for every new mapping made. The delta type
here would be 'independent' with a value of +1. The table bellow shows other
possible algorithms for mapping deltas and values. With knowledge of the
NAT and delta we can move to the last section.

.. csv-table::
    :file: ../../diagrams/delta_characteristics.csv
    :header-rows: 1

----

Putting it all together
--------------------------

NATs are mostly based on the assumption of dynamically allowing a destination
server. The server here is already reachable over the Internet but the interesting
part is that it **need not be.** There's two scenarios where this makes sense.

UDP hole punching
^^^^^^^^^^^^^^^^^^^

UDP is 'connectionless' and if you can get two computers behind NATs to exchange
packets to each others respective mappings (while controlling what mapping you
get assigned to the extent that you can) then a UDP session between both sides
can be created.

TCP hole punching
^^^^^^^^^^^^^^^^^^^^^

A regular TCP connection starts with a three-way handshake consisting of SYN,
SYN-ACK, and ACK packets. Normally a connection is created by calling connect()
and pointing it at a listen()ing server which accept()s it. However, there is
a strange and little known way to achieve a connection where both sides call
connect() on each others external IP:port mappings at the same time.

What needs to occur is the SYN packets for both sides need to cross their 
routers NAT before the other arrives. If it does not the router
has no rule for the inbound IP and sends a reset. But if the two sides are synchronized a new TCP connection is formed.

.. image:: ../../diagrams/tcp_hole_punching_detailed.png
    :alt: Combined NAT prediction with TCP hole punching

.. NOTE::
    NAT type and delta type facilitate prediction of external mappings.
    Mappings are the ports a router assigns for use by a LAN IP and port.
    UDP and TCP hole punching depend on predicting mappings of
    peers. Hence the need to analyze NAT behaviors.

See nat_test.py, nat_predict.py, and nat_utils.py for implementation.

----

Credits
---------

It's important to note that the information on this page came from many sources
including papers. They weren't my ideas. The STUN client that P2PD
uses was originally from jtriley/pystun. That client has since been replaced
to reuse the same message definitions from my TURN client to reduce duplication.
While the NAT test code was re-written completely to make the tests near instant,
support IPv6, and fix bugs in the original code.

The information here on delta types came from research papers on NAT
characteristics. I implemented the algorithms to characterize delta types
based on the descriptions of how they worked from papers. Consider
such research make by other people.