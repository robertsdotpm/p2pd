# Connections

This page explains how to connect two nodes and how to use the resulting Pipe.

## auto_connect

```python
from warpgate.node.auto_connect import auto_connect

pipe, plugin = await auto_connect(node, dest_addr, timeout=60.0)
```

`auto_connect` is the high-level connection API. It:

1. Resolves `dest_addr` (raw bytes or a PNP nickname string)
2. Builds every valid *(plugin, address-family, route-type)* combination
3. Launches all combinations concurrently
4. Returns `(pipe, plugin)` for the first successful connection
5. Cancels and cleans up everything else

```
dest_addr ──► resolve ──► dest_map
                               │
                    build combos (plugin × AF × route_type)
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
   direct_connect        reverse_connect          punch
   (IP4, NIC_BIND)      (IP4, NIC_BIND)    (IP4, NIC_BIND)
          │                    │                    │
          └────────────────────┼────────────────────┘
                               │
                          race results
                               │
                      (pipe, winning_plugin)
```

If all direct strategies fail, `auto_connect` tries TURN (relay) as a fallback,
up to `turn_limit` times (default 3).

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `node` | — | The local Node |
| `dest_addr` | — | Peer's address bytes or PNP nickname |
| `timeout` | `60.0` | Seconds to wait for any plugin to succeed |
| `turn_limit` | `3` | Max TURN attempts if direct strategies all fail |

Returns `(None, None)` if everything fails within the timeout.

## node.connect (manual)

For fine-grained control, use `node.connect` directly:

```python
from aionetiface import IP4, NIC_BIND

plugin = await node.connect(
    af=IP4,
    route_type=NIC_BIND,
    pnp_addr=dest_addr,
    plugin_name="direct_connect",
)
pipe = await asyncio.wait_for(plugin.result, timeout=10)
```

`node.connect` returns a plugin object whose `.result` is an `asyncio.Future`
that resolves to a `Pipe` when the connection succeeds.

### address families

| Constant | Meaning |
|----------|---------|
| `IP4` | IPv4 only |
| `IP6` | IPv6 only |

Pass `None` to let warpgate pick the first AF both nodes share.

### route types

| Constant | Meaning |
|----------|---------|
| `NIC_BIND` | Use the NIC's private/local IP (LAN or same-machine) |
| `EXT_BIND` | Use the external/public IP (WAN path through NAT) |

## Pipe API

Once you have a `Pipe`, you communicate with it like this:

### Subscribing

Before you can receive messages you must subscribe. A subscription tells warpgate
which messages you're interested in:

```python
from aionetiface import SUB_ALL

pipe.subscribe(SUB_ALL)   # match any message from any sender
```

`SUB_ALL` is the wildcard. You can also filter by content pattern or sender:

```python
# Only messages matching a regex pattern
pipe.subscribe((b"^HELLO", None))

# Only messages from a specific sender
pipe.subscribe((None, ("192.168.1.5", 12345)))

# Deliver matching messages directly to a callback instead of a queue
pipe.subscribe(SUB_ALL, handler=my_async_func)
```

A subscription returns an offset integer you can use with `unsubscribe`.

### Sending

```python
await pipe.send(b"hello world", dest_tup)
```

For TCP pipes you established with `auto_connect`, you can omit `dest_tup`:

```python
await pipe.send(b"hello world", None)
```

For UDP, always pass the destination tuple `(ip, port)`.

### Receiving

```python
data = await pipe.recv(SUB_ALL)                  # returns bytes or None on timeout
data = await pipe.recv(SUB_ALL, timeout=5)        # custom timeout in seconds
tup  = await pipe.recv(SUB_ALL, full=True)        # returns [(ip, port), data]
```

`recv` blocks until a matching message arrives. Default timeout is 2 seconds.

### Receiving N bytes

For stream protocols where you need an exact byte count:

```python
data = await pipe.recv_n(1024, SUB_ALL)   # accumulates until >= 1024 bytes
```

### Closing

```python
await pipe.close()
```

Always close pipes when you're done. Unclosed pipes keep the underlying socket open.

## Receiving on the server side

The server-side node receives messages through `node.add_msg_cb`:

```python
async def on_message(msg, client_tup, pipe):
    ip, port = client_tup
    print("Received {} bytes from {}:{}".format(len(msg), ip, port))
    await pipe.send(b"got it", client_tup)

node.add_msg_cb(on_message)
```

This fires for every message on every server socket the node manages.

## Connection patterns

### Ping-pong (request-response)

```python
# Sender side:
pipe.subscribe(SUB_ALL)
await pipe.send(b"ping", dest)
resp = await pipe.recv(SUB_ALL)   # b"pong"

# Receiver side:
async def on_msg(msg, client_tup, pipe):
    if msg == b"ping":
        await pipe.send(b"pong", client_tup)

node.add_msg_cb(on_msg)
```

### Streaming

```python
for chunk in data_chunks:
    await pipe.send(chunk, dest)

# Receiver accumulates with recv_n:
full_data = await pipe.recv_n(total_size, SUB_ALL)
```

### Broadcast (one sender, multiple receivers)

There is no built-in broadcast. Create a `Pipe` to each receiver and send to all:

```python
pipes = []
for addr in peer_addresses:
    p, _ = await auto_connect(node, addr)
    pipes.append(p)

for p in pipes:
    await p.send(b"broadcast message", None)
```

## Inbound connections

When another node connects to yours, the message arrives through `msg_cb`. To
get the pipe itself for bidirectional use:

```python
pipe_id = "my-session-id"
future = node.pipe_future(pipe_id)

# The connecting peer sends the pipe_id in its first message.
# Your msg_cb calls:
async def on_msg(msg, client_tup, pipe):
    if msg.startswith(b"CONNECT:"):
        pipe_id = msg[8:].decode()
        node.pipe_ready(pipe_id, pipe)

node.add_msg_cb(on_msg)

# Then you await the future to get the pipe:
inbound_pipe = await asyncio.wait_for(future, timeout=10)
```

The `direct_connect` plugin uses this pattern internally with `CON_ID_MSG`.
