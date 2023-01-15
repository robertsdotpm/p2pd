# P2PD

``[Coverage >= 82%] [Python >= 3.6] [Mac, Win, Nix, BSD, Android]``

**P2PD** is a new async networking library for Python. It's based on solving some of the problems with Python's existing APIs and supports P2P networking among other features.

Let's look at some examples.
Start the Python REPL with await support with:

> python3 -m asyncio

Initialise information about your network interfaces.

```python
from p2pd import *
netifaces = await init_p2pd() # Same API as netifaces
```

Load default interface and load details about it's NAT.

```python
i = await Interface(netifaces=netifaces)
await i.load_nat()
```

Choose an external address to use for an endpoint.
Resolve the address of an echo server.

```python
route = await i.route().bind()
dest = await Address("p2pd.net", 7, route)
```

Build an async UDP pipe to the server.

```python
pipe = await pipe_open(UDP, dest, route)
pipe.subscribe()
```

Do some I/O on the pipe and cleanup.

```python
# UDP so may not arrive.
await pipe.send(b"some message", dest_tup)
out = await pipe.recv(timeout=2)
print(out)
```

## P2P networking

How about an example that does P2P networking?

```python
from p2pd import *

# Put your custom protocol code here.
async def custom_protocol(msg, client_tup, pipe):
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
    node.add_msg_cb(custom_protocol)
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
    assert(msg in out)
    await pipe.close()
    await node.close()

# Run the coroutine.
# Or await make_p2p_con() if in async REPL.
async_test(make_p2p_con)
```

In this example the node connects to itself but it could just as easily be used to connect to another peer.

## Features

**P2PD** is a new project aiming to make peer-to-peer networking
simple and ubiquitous. P2PD can be used either as a library or as a service.
As a library P2PD is written in Python 3 using asyncio for everything.
As a service P2PD provides a REST API on http://127.0.0.1:12333/.
The REST API is provided for non-Python languages.

P2PD offers engineers the following features:

- Multiple strategies for establishing peer-to-peer direct connections.

  - **Direct connect** = Connect to a reachable node.
  - **Reverse connect** = Tell a node to connect to you.
  - **TCP hole punching** = Simultaneous TCP connections.
  - **TURN** = Use a proxy server as a last resort.
- **Advanced NAT detection.** P2PD can detect 7 different types of NATs and
   5 different sub-types for a combined total of **35 unique NAT
   configurations.** The result is better NAT bypass.
- **Smart TCP hole punching.** The TCP hole punching algorithm has been
   designed to require minimal communication between peers to increase
   the chances of success. The algorithm supports a diverse number of
   NAT configurations for the best results possible.
- **Port forwarding (IPv4) and pin hole (IPv6.)** Automatically
   handles openning ports on the router to increase reachability.
- **IPv6 ready from day 1.** Supports IPv4 and IPv6. Introduces a new
   format for addresses that offers insight into a peer's
   NIC cards, internal network, and NAT devices.
- **A new way to do network programming.** Focuses on NICs as the
   starting point for building services. Introduces 'routes' as a
   way to provide visibility into external addresses. You can build
   services that support IPv4, IPv6, TCP, and UDP without writing
   different code for each of them.
- **Language-agnostic REST API.** You can call **/p2p/open/name/addr**
   then **/p2p/pipe/name** to turn any HTTP connection into a two-way relay
   between a peer-to-peer connection.
- **Minimal dependencies.** Most of the code in P2PD uses the Python
  standard library to improve portability and reduce packaging issues.
- **Built on open protocols.** P2PD uses **STUN** for address lookups,
   **MQTT** for signaling messages, and **TURN** for last resort proxying.
   All of these protocols have public infrastructure.

Learn how to use the software:
https://p2pd.readthedocs.io/
