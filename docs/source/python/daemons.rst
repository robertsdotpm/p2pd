Daemons
========

In the :doc:`pipes` section I showed some simple examples of how servers
can be built using the `pipe_open` function. Such an approach is fine if
you only want to use one protocol or address type. But real-world servers
may need to run on multiple routes, address, and interfaces. The
Daemon class offers a way to build such servers.

To use it you sub class it and define your own msg_cb function.

listen_all
-----------

.. literalinclude:: examples/example_8.py
    :language: python3

The listen_all method of the Daemon class is as follows.

.. code-block:: python

    async def listen_all(self, targets, ports, protos, af=AF_ANY, msg_cb=None,  error_on_af=0)

Targets, ports, and protos are a list. The supported objects that can be used
as targets are Interfaces and Routes. A range may be given as an entry in
the ports list by using [start, stop] (inclusive.) The total number of
servers created will be len(targets) * total_ports * len(protos) * total_afs.
For example::

    targets = [i, r]
    ports = [10000, [30000, 30100]]
    protos = [TCP]
    af = AF_ANY (use all supported address families of the related interface.)

Let's assume that i and r use duel-stack interface. The total servers would be
2 * 101 * 1 * 2 = 404 so it can add up fast if you're not careful. It should
be noted that any Route objects passed as targets will have their bound
information ignored if they're already bound. But their NIC IPs and EXT IPs
will still be used as a template to create routes for the servers
based on the other parameters used for listen_all.

.. note::

    **IPv6 note**: P2PD has small differences in the way it handles IPv6
    services compared to IPv4 which would be unexpected without learning
    about them. In IPv4 to run a server on a network interface that can be reached
    from the LAN and WAN you simply listen on one of the NICs IPs.
    In IPv6 it has kind of split up LAN IPs and external IPs into
    link-local addresses and global-scope addresses, respectively.
    
    I wanted the code to work the same with IPv6 so I start with the assumption that users want servers to be reachable internally and externally. Hence I don't just bind to a global-scope address. I also bind to a link-local address. That means that for IPv6 the final number of servers created
    is multipled by 2. Maybe this is a bad idea but I think it simplifies
    a lot of things.

listen_specific
----------------

The listen_all function is useful for applying the same AFs, protocols, and ports to the entries in the targets list. But sometimes you want to use the targets as-is if they're already 'bound.' Perhaps in the case where they've been specifically set to bind to a loopback adapter or even 'all addresses.'

.. code-block:: python

    async def listen_specific(self, targets, msg_cb=None)

The format of targets here is given as **[[target, protocol], ...]**.

.. literalinclude:: examples/example_9.py
    :language: python3

The listen_specific code hasn't been tested too much so it's better to use **listen_all**.