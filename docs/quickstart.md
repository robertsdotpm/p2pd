# Quickstart

This guide shows two peers exchanging a message.  It's the smallest
useful P2PD program and a good base for your own code.

## Two peers, one message

```python
import asyncio
from p2pd import Gate, peer
from aionetiface import SUB_ALL


async def echo(link):
    async for msg in link:
        await link.send(b"echo:" + msg)


async def alice():
    async with Gate("alice") as gate:
        await gate.listen(echo)            # blocks; calls echo(link) per peer


async def bob():
    async with Gate("bob") as gate:
        pipe, _ = await gate.connect(peer.find("alice"))
        pipe.subscribe(SUB_ALL)
        await pipe.send(b"hi")
        print(await pipe.recv(SUB_ALL))    # b"echo:hi"


asyncio.run(asyncio.gather(alice(), bob()))
```

Both peers register on the public nickname server, race every
available traversal strategy until one connects, and exchange a
message.

## What's happening

### `Gate("alice")`

`Gate` is the high-level wrapper around `Node`.  Constructing it with
a name does three things:

1. Loads (or generates + persists) an ECDSA keypair under
   `~/aionetiface/alice.json`.  Same name on the same machine → same
   key.  Different name (or no name) → fresh identity.
2. Starts a `Node` underneath: discovers NICs, opens listen sockets,
   classifies the local NAT, syncs NTP, connects to MQTT brokers.
3. Registers `alice.p2p` on the namebump nickname server so peers can
   resolve the name to the node's full address (with all
   per-interface paths and broker hints).

If you don't pass a name, `Gate()` derives a deterministic one from
the host's NIC MAC addresses — useful for unattended nodes.

### `gate.listen(handler)`

Blocks accepting inbound peers.  For each peer that connects,
`handler(link)` is scheduled as a background task.  Each `link` is a
`HandlerPipe` exposing `async for msg in link` (read) and
`await link.send(msg)` (write).

```python
async def echo(link):
    async for msg in link:
        await link.send(b"echo:" + msg)

await gate.listen(echo)
```

### `peer.find("alice")`

Returns a `PeerHandle` — an opaque token saying "the peer registered
as `alice.<active_tld>`".  When the input has no TLD, `peer.find`
auto-appends the active one (`.p2p` for the default single-server PNP
config).  No network call yet; the actual nickname resolution happens
inside `gate.connect`.

### `gate.connect(target)`

Resolves the handle (one namebump GET), then runs `auto_connect`:

1. Builds every valid `(plugin, address-family, route-type)` combo
   between the two peers.
2. Launches every combo concurrently.
3. Cancels the losers as soon as one wins.

Returns `(pipe, plugin)` — the live `Pipe` and the plugin instance
that won, or `(None, None)` on failure.  Use `pipe.send`,
`pipe.subscribe`, and `pipe.recv` from there (see
[connections.md](connections.md)).

Plugins tried, in phase order: `direct_connect`, `reverse_connect`,
`tcp_punch`, `udp_punch`, `random_probe`, then `turn` as a last-resort
relay.

## Bytes-only addressing (no nickname server)

If you don't want to depend on the public nickname server, share raw
address bytes out-of-band:

```python
import asyncio
from p2pd import Gate
from aionetiface import SUB_ALL


async def echo(link):
    async for msg in link:
        await link.send(b"echo:" + msg)


async def alice():
    async with Gate() as gate:
        addr = gate.node.address()         # bytes
        share_with_bob(addr)               # however you like
        await gate.listen(echo)


async def bob(alice_addr_bytes):
    async with Gate() as gate:
        pipe, _ = await gate.connect(alice_addr_bytes)
        pipe.subscribe(SUB_ALL)
        await pipe.send(b"hi")
        print(await pipe.recv(SUB_ALL))
```

`gate.connect` accepts either a `PeerHandle` (resolved via namebump),
a `<name>.p2p` string (likewise), or raw `bytes` (the addr serialised
by `node.address()`).

## Skipping the Gate wrapper

For full control over message callbacks, manual plugin selection,
explicit interface lists, etc., drop down to the `Node` API.
See [nodes.md](nodes.md) and [connections.md](connections.md).

```python
import asyncio
from p2pd import Node
from p2pd.node.auto_connect import auto_connect
from aionetiface import SUB_ALL


async def main():
    alice = await Node().start()
    bob   = await Node().start()
    pipe,    _ = await auto_connect(alice, bob.address())
    bob_pipe, _ = await auto_connect(bob, alice.address())
    bob_pipe.subscribe(SUB_ALL)
    await pipe.send(b"hi")
    print(await bob_pipe.recv(SUB_ALL))     # b"hi"
    await pipe.close(); await bob_pipe.close()
    await alice.close(); await bob.close()


asyncio.run(main())
```

## Test-mode startup

Real `Gate` / `Node` startup contacts STUN servers, MQTT brokers, and
the nickname server.  In tests you usually want none of that:

```python
from p2pd import Node
from p2pd.node.node_defs import NODE_TEST_CONF

node = await Node(conf=NODE_TEST_CONF).start()
```

`NODE_TEST_CONF` disables UPnP, NTP, STUN, and PNP, so the node comes
up in milliseconds and only talks loopback.
