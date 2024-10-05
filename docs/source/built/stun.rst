STUN client for address lookups
=================================

STUN is a protocol that can be used to lookup a computers IP address. It
provides information on external port mappings and some servers also support
being able to send replies back from different IP addresses. These servers
are very important [for peer-to-peer networking] because they allow for
the determination of any NATs used by a home router.

There are many public STUN servers that can be used for basic functionality.
P2PD uses STUN to determine WAN IPs, NAT details, and port mappings.
Here is how to use the STUN client.

.. literalinclude:: ../../examples/example_12.py
    :language: python3

STUN magic cookies
-------------------

The first RFC that introduced STUN was RFC 3489. In this version of the protocol
you're able to specify whether the STUN server sends a reply from a different IP
or port. Being able to do this is significant because it lets you determine
the kind of NAT for a router. The basic version of STUN supports 'bind'
requests -- where the server will reply with your external IP and port.

Later versions of STUN removed the ability to specify that a reply should come
from a different IP or port. People writing STUN software should know about this.
It's not just about having the right protocol messages. Many public STUN
servers will only support more recent versions of the protocol so that if you're
not sending the magic cookie they won't even reply.

.. csv-table::
    :file: ../../diagrams/stun_rfcs.csv
    :header-rows: 1

.. TIP::
    A new field for the magic cookie wasn't added to the packet. Instead,
    the first 4 bytes of the 16 byte TXID were reserved for the magic cookie.
    Thus: as long as these bytes ARE NOT set to the magic cookie you are signaling
    your desire to use RFC 3489 capabilities.