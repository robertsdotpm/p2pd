STUN client for address lookups
=================================

STUN is a protocol that can be used to lookup a peer's external address. It also
provides information on port mappings and some servers with multiple addresses
support the optional feature of receiving connections back from another address.
Consequently, such servers allow one to determine the type of NAT you're
behind (if any.)

There are many public STUN servers that can be used for basic functionality.
P2PD uses STUN to build route pools and NAT information for interfaces.
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

Now, if you know about this you'll be able to write STUN software that can correctly
classify what versions of the protocol they support and optimize how many servers
your software can support. This is something I've had to do with P2PD and the
p2pd/scripts folder has some code in there for how I did that. Bellow are the
key takeaways from the RFC changes.

.. csv-table::
    :file: ../../diagrams/stun_rfcs.csv
    :header-rows: 1

.. TIP::
    A new field for the magic cookie wasn't added to the packet. Instead,
    the first 4 bytes of the 16 byte TXID were reserved for the magic cookie.
    Thus: as long as these bytes ARE NOT set to the magic cookie you are signaling
    your desire to use RFC 3489 capabilities.