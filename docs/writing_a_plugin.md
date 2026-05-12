# Writing a Plugin

This guide walks through building a custom traversal plugin from scratch.

A plugin is responsible for one thing: producing a `Pipe` between two
nodes.  When it succeeds, it resolves `self.result` with the pipe.
When it fails, it resolves `self.result` with `None` (or just lets the
TraversalManager's `finally` do it for you on exception).

## The minimum

```python
from warpgate import Plugin, register


@register(phase="direct")
class DirectTCP(Plugin):
    name = "direct_tcp"
    transport = "tcp"

    async def run(self, reply=None):
        if self.af not in self.nic.supported():
            return self.result.set_result(None)         # skip
        route = await self.nic.route(self.af).bind()
        pipe = await route.connect(
            (self.dest_info["ip"], self.dest_info["port"])
        )
        self.result.set_result(pipe)                    # winner
```

Drop this in `src/warpgate/traversal/plugins/<dir>/main.py` (or anywhere
on the Python path that gets imported during node startup) and the
plugin loader picks it up automatically — `@register` adds the class
to `plugin_registry` at import time, and `node.start()` walks that
registry to install everything onto the `TraversalManager`.

## The class-attribute contract

Everything the framework needs lives in lowercase class attributes
on the `Plugin` subclass:

| attr | required | what it does |
| --- | --- | --- |
| `name` | yes | Human-readable name, also the wire-protocol id used in `ConMsg.meta.plugin_name` |
| `transport` | yes | `"tcp"` or `"udp"` |
| `route_types` | no | Tuple of route types this plugin supports.  Default is all three: `(NIC_BIND, EXT_BIND, LOOPBACK_BIND)` |
| `conf` | no | Plugin config dict.  Currently the framework reads `timeout` (seconds, default 10) and `set_bind` (default False).  See `traversal_manager.install_plugin` for the full shape. |
| `proto_messages` | no | Tuple of `(MsgClass, strategy_enum, ttl)` triples.  Used by plugins that need a custom signal-channel message type. |
| `phase` | yes (set by `@register`) | One of `"direct"`, `"punch"`, `"spray"`, `"relay"`, or `None`.  `auto_connect` walks phases in this order and stops as soon as one succeeds. |

`@register(phase=...)` writes `phase` onto the class for you — you
don't set it manually.

## What `run()` gets

By the time `run(self, reply=None)` is called, the framework has
already populated the plugin instance with everything it needs:

| attribute | type | description |
| --- | --- | --- |
| `self.result` | `asyncio.Future` | Resolve to a `Pipe` on success, or `None` on failure |
| `self.plugin_id` | `str` | 15-char random id, used for inbound-pipe routing |
| `self.af` | `IP4` or `IP6` | Address family this attempt uses |
| `self.nic` | `Interface` | The local NIC selected for this attempt |
| `self.src_info` | `dict` | Local addressing — `ip`, `port`, `nic`, `ext`, `nat`, `if_index`, … |
| `self.dest_info` | `dict` | Same fields for the peer |
| `self.route_type` | constant | `NIC_BIND`, `EXT_BIND`, or `LOOPBACK_BIND` |
| `self.same_machine` | `bool` | True if both peers share a `machine_id` |
| `self.timeout` | `int` | Seconds; `auto_connect`'s outer await uses this + a small margin |

`reply` is the inbound signal message that triggered this `run()`
call, or `None` on the first invocation.  Plugins that exchange
multiple signal messages (`tcp_punch`, `udp_punch`, `random_probe`)
get re-entered with `reply` set to whatever the peer sent back.

## Resolving `self.result`

Three contracts:

```python
self.result.set_result(pipe)         # success
self.result.set_result(None)         # explicit fail-fast
return                               # implicit fail (manager resolves to None)
```

The TraversalManager wraps every `run()` in a try/except that catches
`asyncio.TimeoutError`, `OSError`, `ConnectionError`, and any
uncaught `Exception`, and resolves `self.result` to `None` on each.
You can let exceptions propagate; you don't need to swallow them
yourself just to satisfy the future contract.

What you **must not** do is exit `run()` after spawning a background
task that will resolve the future later, without leaving the future
unresolved — the manager only fast-fails on exception paths, not on
normal returns, so a background-task plugin (like `tcp_punch`) keeps
working.

## Phases

`auto_connect` walks phases in this order:

```text
direct → punch → spray → relay
```

Within a phase, every plugin is tried concurrently across every valid
`(af, route_type, src_nic, dest_nic)` combination.  As soon as one
combo wins, the rest are cancelled and the next phase is skipped.
Plugins registered with `phase=None` are auxiliary (e.g. `get_addr`,
`return_addr`, `fan_out`) — `auto_connect` doesn't dispatch them.

Pick the phase that matches the strategy:

| phase | for | examples |
| --- | --- | --- |
| `direct` | tries that work without coordination | `direct_connect`, `reverse_connect` |
| `punch` | NTP-aligned simultaneous-open | `tcp_punch` |
| `spray` | parallel UDP probe rendezvous | `udp_punch`, `random_probe` |
| `relay` | last-resort relays | `turn` |

## Signal-coordinated example

This is `reverse_connect`, slightly trimmed:

```python
from warpgate import Plugin, register
from warpgate.protocol.proto_msg import ConMsg


@register(phase="direct")
class ReverseConnect(Plugin):
    name = "reverse_connect"
    transport = "tcp"

    async def run(self, reply=None):
        # Tell the peer to dial back at us using their direct_connect.
        msg = ConMsg()
        msg.meta.plugin_name = "direct_connect"

        # Reserve the inbound future BEFORE sending — a fast peer could
        # connect back before we register, otherwise.
        self.register_inbound()
        await self.send_signal_msg(msg)

        # Block until the peer's TCP connect lands and the inbound
        # dispatcher routes it to our reserved future.
        pipe = await self.wait_for_inbound()
        self.result.set_result(pipe)
```

Key helpers:

- `self.register_inbound()` — claim an inbound-pipe slot under
  `self.plugin_id`.  The inbound dispatcher routes any incoming
  connection that carries this plugin_id back to your future.
- `self.wait_for_inbound()` — await the slot you just registered.
- `self.send_signal_msg(msg)` — push a `ConMsg`-shaped object out
  through the MQTT signal channel.

## Custom signal types

Need a multi-round handshake (like the punch plugins)?  Define a
message class in your plugin's `proto.py`, then register it via
`proto_messages`:

```python
from warpgate import Plugin, register
from .proto import MyHandshakeMsg

P2P_MY_PROTO = 99


@register(phase="punch")
class MyHandshake(Plugin):
    name = "my_handshake"
    transport = "udp"
    proto_messages = (
        (MyHandshakeMsg, P2P_MY_PROTO, 18),     # (msg_class, strategy_id, ttl_secs)
    )

    async def run(self, reply=None):
        if reply is None:
            # First call — initiator side.
            outgoing = MyHandshakeMsg(...)
            outgoing.meta.plugin_name = "my_handshake"
            await self.send_signal_msg(outgoing)
            return                               # wait for peer reply
        # Second call — reply-handler side.
        ...
        self.result.set_result(pipe)
```

The plugin loader patches `WIRE_NAME = "<plugin_name>.<MsgClassName>"`
onto the message class so it round-trips through pack/unpack
automatically.

## Factory plugins

When the plugin needs node-level shared state (TURN server pool,
process pool, persistent NAT classifier), use a `setup` classmethod
instead of letting the loader instantiate the class directly:

```python
@register(phase="relay")
class TURNRelay(Plugin):
    name = "turn"
    transport = "udp"

    @classmethod
    async def setup(cls, node):
        if not node.conf.get("enable_turn", True):
            return None                          # skip — plugin disabled
        factory = TURNFactory(node)
        node.resources.register(factory)         # auto-close on shutdown
        return factory                           # used as the per-attempt builder

    async def run(self, reply=None):
        ...
```

The returned factory's `build_plugin()` is called once per connection
attempt; whatever it returns must be a `Plugin` instance.  Returning
`None` from `setup` removes the plugin from the registry entirely.

## Testing

Use `NODE_TEST_CONF` so the test doesn't need MQTT / STUN / PNP:

```python
import unittest
from aionetiface.testing import AsyncTestCase
from warpgate import Node
from warpgate.node.node_defs import NODE_TEST_CONF
from warpgate.node.auto_connect import auto_connect


class TestMyPlugin(AsyncTestCase):
    async def test_connects(self):
        alice = await Node(conf=NODE_TEST_CONF).start()
        bob   = await Node(conf=NODE_TEST_CONF).start()
        try:
            pipe, _ = await auto_connect(alice, bob.address())
            self.assertIsNotNone(pipe)
        finally:
            await alice.close()
            await bob.close()
```

To narrow `auto_connect` down to your plugin only, clear the
manager's plugin_loaders before the call:

```python
for n in (alice, bob):
    n.traversal.plugin_loaders.clear()
    n.traversal.install_plugin("my_plugin", {"class": MyPlugin})
```

## Checklist

- [ ] `@register(phase="direct"|"punch"|"spray"|"relay"|None)` on the class
- [ ] Subclass `Plugin`
- [ ] Set `name` and `transport` class attrs
- [ ] (Optional) `route_types`, `conf`, `proto_messages`, `setup`
- [ ] `async def run(self, reply=None)` that resolves `self.result`
- [ ] On any failure: `self.result.set_result(None)` (or just raise — the manager handles it)
- [ ] Register inbound *before* sending signals, not after
- [ ] Drop the file at `src/warpgate/traversal/plugins/<name>/main.py` for auto-discovery, or expose it via the `warpgate.strategies` entry-point group
