Quick start
============

Installation
-------------

P2PD is on PyPI.  Install it with:

.. parsed-literal::

    python3 -m pip install p2pd

This automatically pulls in the three companion packages P2PD depends on:

- **aionetiface** — async network interface detection, routing, STUN client.
- **sidewire** — P2P protocol message serialisation.
- **namebump** — client for the PNP (Peer Name Protocol) naming system.

To install from source (for running the test suite):

.. parsed-literal::

    git clone https://github.com/robertsdotpm/p2pd.git
    cd p2pd
    python3 -m pip install -e .
    python3 -m pip install -r optional-test-requirements.txt

----

Your first node in 30 seconds
--------------------------------

Every P2PD program starts with a :class:`P2PNode`.  The node:

1. Loads your network interfaces and discovers external IPs via STUN.
2. Opens MQTT connections for peer signaling.
3. Synchronises the clock with NTP (needed for hole punching).
4. Optionally requests UPnP port forwarding from your router.

.. code-block:: python

    from p2pd import *
    import asyncio

    async def msg_cb(msg, client_tup, pipe):
        if b"PING" in msg:
            await pipe.send(b"PONG", client_tup)

    async def example():
        async with P2PNode() as node:
            node.add_msg_cb(msg_cb)
            print("Address:", node.addr_bytes.decode())
            await asyncio.sleep(60)   # keep running

    async_test(example)

The ``async with`` block starts the node on entry and shuts it down
cleanly on exit.  ``node.addr_bytes`` is the full serialised address
other peers need to connect to you.

----

Ping-pong across two machines
--------------------------------

The example below shows a complete server-and-client workflow.  Run it
from the ``docs/examples/`` directory.

.. literalinclude:: ../../examples/guide_01_ping_pong.py
   :language: python3

**Terminal 1 (server):**

.. parsed-literal::

    python3 docs/examples/guide_01_ping_pong.py server
    Server nickname (share this): pingpong.peer
    Waiting for connections (Ctrl-C to stop)...

**Terminal 2 (client):**

.. parsed-literal::

    python3 docs/examples/guide_01_ping_pong.py client pingpong.peer
    Connecting to pingpong.peer ...
    Got: b'PONG'
    Success!

The server registers a nickname so you don't have to copy the full
address.  See :doc:`nicknames` for how the naming system works.

----

What happens when ``connect()`` is called
-------------------------------------------

P2PD tries four traversal strategies in order, returning as soon as one
succeeds:

.. code-block:: text

    node.connect("peer.name")
         │
         ├─── 1. Direct connect     (is the peer publicly reachable?)
         ├─── 2. Reverse connect    (ask the peer to call us back via MQTT)
         ├─── 3. TCP hole punching  (simultaneous SYN from both sides)
         └─── 4. TURN relay         (proxy via public TURN server)

Each strategy is tried across all your network interfaces and both IPv4
and IPv6.  See :doc:`strategies` for a full explanation of each approach.
