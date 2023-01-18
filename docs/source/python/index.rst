Using P2PD from Python
=======================

Before we get started all Python examples assume:

    1. The 'selector' event loop is being used.
    2. The 'spawn' method is used as the multiprocessing start method.
    3. You are familar with how to run asynchronous code.

This keeps the code consistent across platforms. The package sets
these by default so if your application is using a different configuration
it may not work properly with P2PD.

| Let's start with how to open a P2P connection to a peer.
| We'll connect to ourselves for this example.


.. code-block:: python

    from p2pd import *

    # Put your custom protocol code here.
    async def msg_cb(msg, client_tup, pipe):
        # E.G. add a ping feature to your protocol.
        if b"PING" in msg:
            await pipe.send(b"PONG")

    async def make_p2p_con():
        # Initalize p2pd.
        netifaces = await init_p2pd()
        #
        # Start our main node server.
        # The node implements your protocol.
        node = await start_p2p_node(netifaces=netifaces)
        node.add_msg_cb(msg_cb)
        #
        # Spawn a new pipe from a P2P con.
        # Connect to our own node server.
        pipe = await node.connect(node.addr_bytes)
        pipe.subscribe(SUB_ALL)
        #
        # Test send / receive.
        msg = b"test send"
        await pipe.send(b"ECHO " + msg)
        out = await pipe.recv()
        #
        # Cleanup.
        assert msg in out
        await pipe.close()
        await node.close()

    # Run the coroutine.
    # Or await make_p2p_con() if in async REPL.
    async_test(make_p2p_con)

You can use this library as a black box if you want. The code automatically
handles loading network interfaces, enumerating routers, bypassing NATs,
and establishing P2P connections. But you can do far more with P2PD.

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
    - External address suport
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
    turn
    stun
    examples

