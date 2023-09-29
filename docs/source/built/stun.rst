STUN client for address lookups
=================================

STUN is a protocol that can be used to lookup a peer's external address. It also
provides information on port mappings and some servers with multiple addresses
support the optional feature of receiving connections back from another address.
Consequently, such servers allow one to determine the type of NAT you're
behind (if any.)

There are many public STUN servers that can be used for basic functionality.
But very few support TCP, IPv6, or multiple addresses, and the ones that do
are very unreliable and often experience downtime. P2PD uses STUN heavily
to determine the routes that belong to interfaces and their NAT information.
The only way to ensure the software worked reliability was to run a STUN
server with multiple IPv4/6s on TCP and UDP.

Here is how to use the STUN client.

.. literalinclude:: ../python/examples/example_12.py
    :language: python3