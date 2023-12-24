Using P2PD from Python
========================

Before we get started all Python examples assume:

    1. The 'selector' event loop is being used.
    2. The 'spawn' method is used as the multiprocessing start method.
    3. You are familiar with how to run asynchronous code.
    4. The string encoding is "UTF-8."

This keeps the code consistent across platforms. The package sets
these by default so if your application is using a different configuration
it may not work properly with P2PD.

| **Let's start with how to connect to another peer.**

The code has two functions that simulate what two different computers might
run (**computer_a** and **computer_b**.) Since it is usually impractical
for people to directly remember IP address information names are used instead.
Here the naming solution is provided by 'IRCDNS' - a permissioned, key-value
store that P2PD provides running on IRC infrastructure.

.. literalinclude:: examples/example_1.py
    :language: python3

If you use 'IRCDNS' to name your node the first thing to understand is the seed. Seeds are 24 or more cryptographically random bytes (such as from
secrets.token_bytes() or from hashlib.sha3_256) that is used to
generate your account details on IRC networks. Your account details
let you register and update names so you should save your seed!

Names consist of three parts. The main name, the TLD, and an optional password.
For example: ['my awesome name', 'cats', ''] represents 'my awesome name' on the
'cats' TLD with no password. You can point a name to your P2P address by
passing that list to the register call for the node object. Otherwise,
you can set a name to any value node.irc_dns.name_register(value, name, tld, pw) to use a name for a different purpose.

P2PD handles loading interfaces, enumerating routers, bypassing NATs,
and establishing direct connections to other peers. It is useful for
peer-to-peer networking and as a general way to do network programming; Whether
you want to write multi-protocol, multi-address clients or servers. You can
use async or sync callbacks; pull / push style APIs... The software even
has an optional REST API so it can be used outside of Python.

| **If you were to use Python by itself for network programming you would likely**
| **have to implement some of these features:**

    - IPv6-specific socket bind code
        - Link-local address logic
        - Global-address logic
        - Platform-specific logic
    - Interface-specific connection addresses
        - Different for IPv6 link local addresses
        - Different for IPv6 global addresses
    - Interface support (in general)
    - External address support
    - Whether to use 'protocol' classes or 'streams'
        - Protocols = events; streams = async push and pull.
        -   Python doesn't have an async push and pull API for UDP at all
            because Guido van Rossum thought it was a bad idea.
            I don't agree. P2PD can do async awaits on UDP.
            Or it can do event-based programming like the protocol class.
    - Message filtering (useful for UDP protocols)
    - Multiplexing-specific logic for UDP
    - Some very smart hacks to reuse message handling code
        - Python has radically different approaches for TCP cons and servers.
        - While it does not provide the same methods for UDP.
        -   I've created software that provides the same API features
            whether its a server or connection; TCP or UDP; IPv4 or IPv6
    - A naming system

| Fortunately I've done this already!
| The next topics teach you more about network programming with P2PD.

.. toctree::
    basics
    pipes
    queues
    daemons
    examples

