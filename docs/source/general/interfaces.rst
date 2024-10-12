Interfaces
===========================

All network programming in P2PD starts with the network interface card. Usually
your computer will have a 'default' interface that traffic is sent
down based on various routing methods. Let's start by loading this default
interface and interacting with it. Starting the interface looks up all
its addresses and enumerates the NAT of its associated router.

.. literalinclude:: ../../examples/example_2.py
    :language: python3

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
by using the **list_interfaces** function. Interfaces may be virtual,
contain loopback devices, and other adapters that aren't directly
useful for networking. Often we are only interested in the adapters
that are usable for WAN or LAN networking.

.. literalinclude:: ../../examples/example_3.py
    :language: python3

Now you know how to lookup interfaces and start them. It's time to
learn about 'routes.'

----

The addressing problem
-----------------------

Modern event loops make it easy to write high-performance networking code.
The engineers of today are spoiled by such elegant features compared to the
tools available in the early days. But there is still something very basic
missing from the networking toolbox:

**The ability to see your external addressing information**

There are many cases where this information is needed. For example: imagine
a server that listens on multiple IPs such that it is available on more
than one external IP. The server may wish to know what external IPs are
available to it in case it needs to refer a client to another server. The
STUN protocol is the perfect instance where a client can request
a connection back 'from a different IP address' in order to determine
what type of NAT they have.

.. HINT::
    P2PD makes external addressing details available to the programmer.
    Such information avoids having to manually pass details to bind() 
    to use a given external IP.

Routes to the rescue
---------------------

P2PD solves the addressing problem by introducing mappings called 'Routes'.
A Route describes how interface-assigned addresses relate to external addresses.
Each route is indexed by address family. Either IPv4 or IPv6. 

----

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

The software starts by grouping private IPs. It binds to the first
and checks the external IP. The result is a new route with the external IP.
If it finds a public IP for a NIC address it binds to the first IP
in it's range (range if it's a block) and checks the external IP.
If the IPs match it assumes the range is valid. If it matches the
previous route it groups them as the same route. 

Example: the software finds a block of NIC IPs '8.8.0.0/16' with 'public IPs.'
It binds to the first address and sees the external address matches. Seeing that
it assumes this means the whole block is valid without checking every IP.
This becomes a new route. This shows how some machines set their NIC IPs to their
external addresses.

----

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
    
The algorithm for IPv6 routes is slightly different.
All link-local addresses are copied to each route.
While every global address 'EXT' forms a new route.

P2PD uses the EXT portion for IPv6 servers. While it uses the NIC portion
for IPv4. It is assumed that all servers should be publicly reachable.
Though this can be bypassed by specifying IPs directly for bind calls
which is indeed what the P2PD REST server does. 

If that sounds difficult :doc:`daemons` make this easier.

.. HINT::
    There's other 'types' of addresses in IPv6 though they're not
    supported in P2PD for now. Just the equivalent of 'private' and
    'public' addresses.

----

Using a route with a pipe
----------------------------

Connect to Google.com and get a response from it.

.. literalinclude:: ../../examples/example_4.py
    :language: python3

Look closely at the route part. What this code is doing is it's asking for
the first route in the route pool for that address family. The route points
to one or more external addresses (more if it's a block) and 'knowns'
how to setup the tuples for bind to use that external address. Once a route
is bound it can be used in the familiar open_pipe call.

.. HINT::
    You can see from this example that P2PD supports duel-stack networking,
    multiple network interface cards, external addressing, DNS / IP / target parsing,
    and publish-subscribe. But there are many more useful features for
    network programming.

Route pools
--------------

Every interface with Internet access has at least one route in its
route pool. If you don't care about what route you're using you can call the
route function from an interface object. But through
the RoutePool class every single possible external address can be used.

.. code-block:: python

    nic = await Interface()
    x = nic.rp[IP4] # IP4 RoutePool
    y = nic.rp[IP6] # IP6 RoutePool
    print(len(x))
    for r in x:
        # A route to use a single external IP from the pool.
        print(r)

The route pool is designed to make it easy to group multiple external addresses
that may be themselves either single addresses or blocks of IPs into one
object that can be indexed, counted, iterated, and used. In this way its easy
to 'grab an IP' and use it. 