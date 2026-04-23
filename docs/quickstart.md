# Quickstart

This guide shows two nodes on the same machine exchanging a message. It is the
simplest possible p2pd program and a good base for your own code.

A runnable test for everything in this guide lives at
[tests/test_docs_quickstart.py](../tests/test_docs_quickstart.py).

## Two nodes, one message

```python
import asyncio
from p2pd import Node
from p2pd.node.auto_connect import auto_connect
from p2pd.node.node_defs import NODE_TEST_CONF
from aionetiface import SUB_ALL

async def main():
    # Start two nodes. NODE_TEST_CONF disables UPnP, STUN, and NTP sync
    # so startup is instant. Use NODE_CONF for real deployments.
    alice = await Node(conf=NODE_TEST_CONF).start()
    bob   = await Node(conf=NODE_TEST_CONF).start()

    # Each node has an address — a compact bytes value you share with peers.
    alice_addr = alice.address()
    bob_addr   = bob.address()

    # Connect Alice to Bob (and Bob to Alice simultaneously).
    # auto_connect tries every available strategy and returns
    # (pipe, plugin) for the first one that succeeds.
    alice_pipe, _ = await auto_connect(alice, bob_addr)
    bob_pipe,   _ = await auto_connect(bob, alice_addr)

    # Subscribe before sending so we don't miss the message.
    bob_pipe.subscribe(SUB_ALL)

    # Send a message from Alice to Bob.
    await alice_pipe.send(b"hello from alice")

    # Bob reads it.
    msg = await bob_pipe.recv(SUB_ALL)
    print(msg)   # b"hello from alice"

    # Clean up.
    await alice_pipe.close()
    await bob_pipe.close()
    await alice.close()
    await bob.close()

asyncio.run(main())
```

## Step by step

### 1. Create and start a Node

```python
node = await Node(conf=NODE_TEST_CONF).start()
```

`Node()` creates the node object. `.start()` runs the startup sequence:
- discovers network interfaces
- generates or loads an identity key
- determines the listen port
- starts TCP/UDP servers on every interface
- (with NODE_CONF) also loads STUN clients, syncs NTP, starts UPnP

`NODE_TEST_CONF` skips the slow network parts so tests run in seconds.

### 2. Get the address

```python
addr = node.address()   # bytes
```

This is a compact serialisation of the node's identity and all its network
addresses. Share it with the peer however you like (socket, file, QR code, …).

### 3. Connect

```python
pipe, plugin = await auto_connect(node, dest_addr)
```

`auto_connect` builds a list of every possible (strategy × address-family ×
route-type) combination, launches them all concurrently, and returns the first
one that produces a live socket. See [Connections](connections.md) for details.

### 4. Subscribe and send

```python
pipe.subscribe(SUB_ALL)       # register a receive queue for all messages
await pipe.send(b"hello")     # send bytes
data = await pipe.recv(SUB_ALL)  # block until data arrives (default 2 s timeout)
```

`SUB_ALL` is a wildcard subscription that matches any message from any sender.
You can create narrower subscriptions — see [Connections](connections.md).

### 5. Close everything

```python
await pipe.close()
await node.close()
```

Always close nodes and pipes when you're done. `Node` is an async context manager,
so you can also write:

```python
async with Node(conf=NODE_TEST_CONF) as node:
    await node.start()
    ...
```

## Real deployment

For real use (not tests), drop `NODE_TEST_CONF`:

```python
node = await Node().start()
```

This enables:
- UPnP port forwarding (helps with home routers)
- STUN clients (needed for hole punching)
- NTP clock sync (coordinates hole-punch timing)
- Nickname registration

Startup takes a few seconds while it contacts public servers.

## Nicknames

Instead of sharing raw address bytes, you can register a human-readable name:

```python
await node.nickname("alice@p2pd")   # register
```

Then the other side can connect using just the name:

```python
pipe, _ = await auto_connect(node, "alice@p2pd")
```

Names expire after a while and must be periodically re-registered. The PNP
(Peer Name Protocol) service is free and public.
