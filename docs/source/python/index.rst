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
run (**computer_a** and **computer_b**.) They both need to know each others 'names'
and addressing information is shared over PDNS (a simple API provided by
a PHP script that implements a key-value store.)

.. literalinclude:: examples/example_1.py
    :language: python3

You can use this library as a black box if you want. The code handles loading network interfaces, enumerating routers, bypassing NATs,
and establishing connections. But even more is possible.

It can be used as a way to do network programming in general. Whether
you want to write multi-protocol, multi-address clients or servers.
Using P2PD makes this simple. And it supports either using async or sync
callbacks  or a pull / push style API. Something like the Python
equivalent of 'protocol classes' versus 'stream reader / writers'
but with more control.

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

| Fortunately I've done this already!
| The next topics teach you more about network programming with P2PD.

.. toctree::
    basics
    pipes
    queues
    daemons
    examples

