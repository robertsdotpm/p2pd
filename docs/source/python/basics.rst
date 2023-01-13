Basics
=======

Running async examples
-------------------------

Alr1ght people, P2PD uses Python's 'asynchronous' features to run
everything in an event loop. You might want to use the special 'REPL'
that the asyncio module provides to run these examples:

.. code-block:: shell

    python3 -m asyncio

.. code-block:: python3

    asyncio REPL 3.11.0
    Use "await" directly instead of "asyncio.run()".
    Type "help", "copyright", "credits" or "license" for more information.
    >>> import asyncio
    >>> from p2pd import *
    >>> netifaces = await init_p2pd() # Loads netifaces.

Now you can simply type `await some_function()` in the REPL to execute it.
If you experience errors in the REPL you'll have to use a regular Python
file for the examples.

Network interface cards
-------------------------

All network programming in P2PD starts with the network interface card. Usually
your computer will have a 'default' interface that all traffic is sent
down based on various routing methods. Let's start by loading this default
interface and interacting with it. Starting the interface looks up all
its internal and external addresses, builds basic routing tables, and
enumerates the NAT qualities of associated gateways.

.. code-block:: python3

    # Start the default interface.
    i = await Interface().start()

    # Load additional NAT details.
    # Restrict, random port NAT assumed by default.
    await i.load_nat()

    # Show the interface details.
    repr(i)

.. code-block:: text

    Interface.from_dict({
        "name": "Intel(R) Wi-Fi 6 AX200 160MHz",
        "nat": {
            "type": 5,
            "nat_info": "restrict port",
            "delta": {
                "type": 6,
                "value": 0
            },
            "delta_info": "random delta (local port == rand port)"
        },
        "rp": {
            "2": [
                {
                    "af": 2,
                    "nic_ips": [
                        {
                            "ip": "192.168.21.21",
                            "cidr": 32,
                            "af": 2
                        }
                    ],
                    "ext_ips": [
                        {
                            "ip": "1.3.3.7",
                            "cidr": 32,
                            "af": 2
                        }
                    ]
                }
            ],
            "23": []
        }
    })

Repr shows a serializable dict representation of the interface after it's
been loaded. You can see a list of interfaces available on your machine
by using the **Interface.list()** function. Interfaces may be virtual,
contain loopback devices, and other adapters that aren't directly
useful for networking. Often we are only interested in the adapters
that are usable for WAN or LAN networking.

.. code-block:: python

    # Returns a list of Interface objects for Inter/networking.
    netifaces = await init_p2pd()
    ifs = await load_interfaces(netifaces=netifaces)

Now you know how to lookup interfaces and start them. It's time to
learn about 'routes.'

The addressing problem
-----------------------

Modern network programming with event loops makes it incredibly easy to write
high-performance networking code. The engineers of today are spoiled by such
elegant features compared to the tools available in the early days. But there
is still something very basic missing from the networking toolbelt:

**The ability to easily know your external addressing information**

There are many cases where this information is needed. For example imagine
a server that listens on multiple IPs such that it is available on more
than one external IP. The server may wish to know what external IPs are
available to it in case it needs to refer a client to another server. The
STUN protocol is an example of just this case where a client can
request a connection back 'from a different IP address' in order to
determine what type of NAT they have.

P2PD makes all external addressing information available to the programmer
so that servers and clients can be aware of their own addresses.

Routes to the rescue
---------------------

P2PD solves the addressing problem by introducing mappings called 'Routes'
to describe how interface-assigned addresses relate to external addresses.
Each route is indexed by address family. Either IPv4 or IPv6. A Route
has the following basic form.

    **[NIC IPR, ...] -> [external IPR]**

**Example 1 -- IPv4 routes**

.. code-block:: text

    NIC IPs:
        192.168.0.20/32 (1 IP)
        193.168.0.0/16 (65024 IPs)
        7.7.7.7/32 (1 IP)
        8.8.0.0/16 (65024 IPs)
    
    EXT IPs:
        1.3.3.7/32 (1 IP)
        8.8.0.0/16 (65024 IPs)
    
    ---------------------------------------------------------------
    Routes:
        [...20, 193..., 7.7.7.7] -> [1.3.3.7]
        [8.8.0.0] -> [8.8.0.0]
    
    Explanation:
        1.  The software starts by grouping all private addresses for a NIC.
            It then binds to one of the addresses and checks the external IP
            using STUN. The result is saved as the external address and this
            becomes a new route. When it finds a public IP for a NIC address
            it binds to the first IP in it's range and checks the external
            IP. Here it finds that 7.7.7.7 results in the same external
            address as the other private IPs and groups them into the same
            route. This demonstrates that public IPs can be assigned to NICs
            and they don't necessarily mean that an IP is externally routable.

        2.  The software finds that when processing the block of IPs '8.8.0.0/16'
            that the external address matches. It assumes that this means the
            whole block is valid without checking every IP. This becomes another
            route. This example shows how some machines set their NIC IPs to
            their external addresses. It also demonstrates how ranges work.
    
**Example 2 -- IPv6 routes**

.. code-block:: text
    
    NIC IPS:
        2020:DEED:BEEF::0000/128 (global scope) (1 IP)
        2020:DEED:DEED::0000/64 (global scope) (a lot of IPs)
        FE80:DEED:BEEF::0000/128 (link-local) (1 IP)
    
    EXT IPS:
        2020:DEED:BEEF::0000/128 (global scope) (1 IP)
        2020:DEED:DEED::0000/64 (global scope) (a lot of IPs)
    
    ---------------------------------------------------------------
    Routes:
        [FE80:DEED:BEEF::0000/128] -> [2020:DEED:BEEF::0000/128]
        [FE80:DEED:BEEF::0000/128] -> [2020:DEED:DEED::0000/64]
    
    Explanation:
        1.  The algorithm for building routes in IPv6 is slightly different to IPv4.
            All link-local addresses for a list and are copied to the NIC
            section of the route. While every global addresss -- whether it's a
            single IP or a block -- creates a new route.
        2.  P2PD uses the EXT portion of routes for IPv6 servers. While it uses
            the NIC portion for IPv4. It is assumed that all servers should be
            publically reachable. Though this can be bypassed by specifying IPs
            directly for bind code which is indeed what the P2PD REST server does.
    
The reason why routes are important is they are used in bind() code to instruct
what external addresses to use for servers or what external addresses will be
visible for outbound traffic. In other words when you bind in P2PD you are
selecting what external addresses to use.

A first networking program
---------------------------

Connect to Google.com and get a response from it.

.. code-block:: python

    from p2pd import *

    async def main():
        #
        # Load default interface.
        i = await Interface().start()
        #
        # Get first supported address family.
        # E.g. if the NIC only supports IPv4 this will == [AF_INET].
        # If it supports both families it will == [AF_INET, AF_INET6].
        # If no AF for route and address specified = use i.supported()[0].
        af = i.supported()[0]
        #
        # Get a route to use for sockets.
        # This will give you a copy of the first route for that address family.
        # Routes belong to an interface and include a reference to it.
        route = await i.route(af).bind()
        #
        # Lookup Google.com's IP address -- specify a specific address family.
        # Most websites support IPv4 but not always IPv6.
        # Interface is needed to resolve some specialty edge-cases.
        dest = await Address("www.google.com", 80, route).res()
        #
        # Now open a TCP connection to that the destination.
        pipe = await pipe_open(TCP, dest, route)
        #
        # Indicate that messages received should also be queued.
        # This enables the pull / push API.
        # You specify regex here. By default it will subscribe to everything.
        pipe.subscribe()
        #
        # Send it a malformed HTTP request.
        buf = b"Test\r\n\r\n"
        await pipe.send(buf)
        #
        # Wait for any message response.
        out = await pipe.recv(timeout=3)
        print(out)
        #
        # Cleanup.
        await pipe.close()

    # From inside the async REPL.
    await main()

You can see from this example that P2PD supports duel-stack networking,
multiple network interface cards, external addressing, DNS / IP / target parsing,
and publish-subscribe. But there are many more useful features for
network programming.

In the next section we'll be taking a closer look at pipes.





