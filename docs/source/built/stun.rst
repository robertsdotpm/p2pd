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

